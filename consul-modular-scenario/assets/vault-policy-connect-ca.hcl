# Existing PKI Mounts
path "/sys/mounts" {
  capabilities = [ "read" ]
}

path "/sys/mounts/connect_root" {
  capabilities = [ "read" ]
}

path "/sys/mounts/connect_inter" {
  capabilities = [ "read" ]
}

path "/connect_root/" {
  capabilities = [ "read" ]
}

path "/connect_root/root/sign-intermediate" {
  capabilities = [ "update" ]
}

path "/connect_inter/*" {
  capabilities = [ "create", "read", "update", "delete", "list" ]
}