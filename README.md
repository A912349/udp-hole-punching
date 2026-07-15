# Home UDP Mesh — первый рабочий слой

Проект содержит два независимых уровня.

- `client.py` — экспериментальный UDP hole punching для пары узлов.
- `server.py` и `mesh_node.py` — control plane и UDP overlay для частичной
  двухуровневой mesh-сети. `server.py` не пересылает пользовательские пакеты.

## Что реализовано

- постоянная X25519-идентичность узла в `mesh-state/identity.json`;
- регистрация cone-суперпиров и обычных клиентов на control server;
- статический двухуровневый граф: near-full backbone и до трёх superpeer для
  каждого клиента;
- Dijkstra для выбора следующего hop, TTL и дедупликация пакетов;
- relay только на cone-суперпирах;
- HMAC-аутентификация внешнего UDP-пакета и ChaCha20-Poly1305 шифрование
  полезной нагрузки между исходным и конечным узлом;
- keepalive/HELLO между соседями;
- публикация локального TCP сервиса и одноразовый запрос/ответ к нему через
  overlay. Это подходит, например, для коротких HTTP-запросов.

## Быстрый запуск

На Linux:

```bash
python3 -m pip install -r requirements.txt
export MESH_NETWORK_TOKEN='длинный-случайный-секрет-минимум-24-символа'
python3 server.py
```

Обычный узел запускается одной командой. По умолчанию он запрашивает роль
`auto`, получает постоянный mesh-IP от coordinator и при наличии cone NAT может
быть выбран superpeer:

```bash
python3 mesh_node.py \
  --server http://SERVER_IP:8001 \
  --network-token "$MESH_NETWORK_TOKEN" \
  --state-dir state-node
```

Для Linux TUN добавьте `--tun-name mesh0 --tun-auto-configure`. У каждого
устройства должен быть свой `--state-dir`. Если устройство никогда не должно
передавать чужой трафик, добавьте `--no-relay`.

Явная роль нужна только для операционного управления: `--role superpeer
--capacity 100` закрепляет relay, а `--role client` запрещает promotion.

Обычный узел, публикующий локальный TCP-сервис:

```bash
python mesh_node.py --server http://SERVER_IP:8001 --network-token "$MESH_NETWORK_TOKEN" \
  --state-dir state-home \
  --service web=127.0.0.1:8080
```

В логе будет напечатан постоянный `node_id` узла. На другом mesh-узле запрос к
сервису отправляется так:

```bash
cat request.bin | python mesh_node.py \
  --server http://SERVER_IP:8001 --network-token "$MESH_NETWORK_TOKEN" \
  --state-dir state-client \
  --call NODE_ID:web > response.bin
```

Для HTTP в `request.bin` должен быть полноценный HTTP-запрос с завершающей
пустой строкой. Текущий сервисный слой читает один ответ размером до 48 KiB.

## Топология и будущий динамический граф

Сейчас сервер строит детерминированный статический граф. В wire protocol и API
уже присутствуют `topology_version`, список link с `cost`, атомарный метод
`apply_topology()` и резервированное поле `graph_update_mode`. Поэтому будущий
оптимизатор может прислать новую версию графа, а узлы заменят маршруты без
изменения формата DATA-пакетов.

Автоматическое изменение графа, измерение нагрузок/RTT, hysteresis и миграция
к резервным superpeer пока намеренно **не включены**: это следующий этап,
который требует наблюдения за реальной сетью и политики выбора узлов.

## Важные ограничения текущей версии

- UDP hole punching из `client.py` пока не встроен в `mesh_node.py`. Mesh-node
  начинает обмен HELLO по endpoint, полученным через STUN; для сложных
  symmetric NAT прямой соседский канал всё ещё должен быть установлен
  существующим transport-слоем или через доступный cone-суперпир.
- Сервисный транспорт пока request/response, а не полноценный надёжный TCP
  tunnel. Для SSH, RDP, долгих HTTP-ответов и потоковых сервисов нужен
  следующий слой: фрагментация, sequence/ack, retransmit, congestion control
  и мультиплексирование потоков.
- Flask development server не предназначен для публичного production
  использования. Перед публикацией нужен TLS reverse proxy, постоянное
  хранилище резервных копий и управление токенами/доступом.

Подробная модель сети находится в [MESH_ARCHITECTURE.md](MESH_ARCHITECTURE.md).
