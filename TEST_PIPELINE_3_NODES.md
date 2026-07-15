# Smoke test: mobile client -> cone superpeer -> home server

В этом тесте четыре роли, но пользовательские данные идут только между тремя mesh-узлами:

```text
mobile client  ->  cone superpeer  ->  home server
                         ^
                         |
              coordinator (only control plane)
```

`server.py` — координирующий сервер. Он выдаёт topology, но HTTP-трафик
домашнего сервиса через него не проходит.

## Перед началом

На всех машинах используйте один и тот же secret, например:

```text
change-this-to-a-long-random-secret-12345
```

На каждой машине нужны зависимости:

```bash
python -m pip install -r requirements.txt
```

Сетевые требования:

- coordinator: входящий TCP `8001` должен быть доступен с Linux-сервера и с
  Android/Termux-устройств;
- superpeer: должен быть за cone NAT, с разрешённым исходящим UDP. Публичный IP
  или port forwarding не нужны: endpoint определяется через STUN на том же UDP
  сокете, а mapping поддерживается keepalive-пакетами;
- home server: публично открывать TCP `8080` не нужно — к нему обращается
  локальный `mesh_node.py`;
- для первого теста мобильный клиент должен иметь cone NAT или проброшенный
  UDP-порт. Полный symmetric NAT hole punching пока не встроен в `mesh_node.py`.

Ниже замените `COORDINATOR_IP` на реальный адрес Linux-сервера.

## 1. Координирующий сервер на Linux

На Linux-сервере:

```bash
export MESH_NETWORK_TOKEN='change-this-to-a-long-random-secret-12345'
export MESH_PORT=8001
python3 server.py
```

Если запускаете под `systemd`, просто пробросьте те же переменные окружения.
Ожидаемый результат: Flask слушает `0.0.0.0:8001`.

## 2. Cone superpeer на Android через Termux

На Android-устройстве в Termux:

```bash
pkg update
pkg install python
python -m pip install -r requirements.txt
```

Затем запустите superpeer:

```bash
python mesh_node.py \
  --server http://COORDINATOR_IP:8001 \
  --network-token 'change-this-to-a-long-random-secret-12345' \
  --role superpeer \
  --nat-type auto \
  --state-dir state-superpeer \
  --capacity 100
```

Сохраняйте строку `Mesh node <NODE_ID> ...` из лога. Узел должен оставаться
запущенным.

Практический момент для Termux:

- не переводите телефон в режим энергосбережения для Termux;
- при возможности держите экран включённым во время первых тестов;
- если Android меняет сеть между Wi-Fi и LTE, лучше перезапустить узел, чтобы
  он заново снял STUN-mapping.

## 3. Домашний сервер с опубликованным сервисом

На home server сначала запустите простой локальный HTTP-сервис:

```bash
python3 -m http.server 8080 --bind 127.0.0.1
```

Во втором окне запустите mesh-узел и опубликуйте этот сервис:

```bash
python mesh_node.py \
  --server http://COORDINATOR_IP:8001 \
  --network-token 'change-this-to-a-long-random-secret-12345' \
  --role client \
  --nat-type auto \
  --state-dir state-home \
  --service web=127.0.0.1:8080
```

Сохраните `NODE_ID` из его лога: далее он обозначен как `HOME_NODE_ID`.

## 4. Мобильный клиент на Android через Termux

На Android-устройстве в Termux создайте файл запроса:

```bash
cat > request.http <<'EOF'
GET / HTTP/1.1
Host: home.mesh
Connection: close

EOF
```

Выполните запрос через overlay:

```bash
python mesh_node.py \
  --server http://COORDINATOR_IP:8001 \
  --network-token 'change-this-to-a-long-random-secret-12345' \
  --role client \
  --nat-type auto \
  --state-dir state-mobile \
  --call HOME_NODE_ID:web \
  --request-file request.http > response.http
```

Просмотрите ответ:

```bash
cat response.http
```

В `response.http` должен быть HTTP-ответ от `python3 -m http.server`.

## Что проверить при ошибке

1. На всех ролях одинаковый `--network-token`.
2. Координатор на Linux доступен по TCP `8001` с Android/Termux.
3. Superpeer на Android действительно получает `cone` в логе.
4. В логах home server и mobile виден `Topology ...: 1 direct neighbors`.
5. `HOME_NODE_ID` — это ID mesh-узла, а не IP-адрес и не ID superpeer.

## Ожидаемый маршрут

```text
SERVICE_REQUEST:
mobile -> superpeer -> home server

SERVICE_RESPONSE:
home server -> superpeer -> mobile
```

Полезная нагрузка шифруется между mobile и home server. Superpeer видит
маршрутный заголовок для пересылки, но не расшифровывает HTTP-запрос.
