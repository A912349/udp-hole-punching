package main

import _ "embed"

//go:embed admin.html
var adminPageHTML string

//go:embed admin.css
var adminCSS string

//go:embed admin.js
var adminJS string
