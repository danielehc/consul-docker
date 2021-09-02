ui = true

storage "file" {
  path = "/vault/data"
}

disable_mlock = true

listener "tcp" {
  address         = "[::]:8200"
  # address = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr = "http://[::]:8200"