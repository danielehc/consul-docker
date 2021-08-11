# Consul Modular Scenario

Modular lab to spin-up a Consul datacenter using custom [Docker][docker] images.

## provision.sh

The only tested script at the moment is `provision.sh`.

### Usage

#### `provision.sh` 

Spins up the environment. It cleans and already existing scenario if found.

#### `provision.sh clean` 

Cleans the environment.

#### `provision.sh ports`

#### `provision.sh env` 

#### `provision.sh help` 



**Warning:** The environment is not intended for production use. It is intended to mimic the behavior of a VM with a container and build test environments to test Consul functionalities without the overhead of deploying a full VM.




[consul]:https://www.consul.io/
[envoy]:https://www.envoyproxy.io/
[docker]:https://www.docker.com/
