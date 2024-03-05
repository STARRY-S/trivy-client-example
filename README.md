# trivy-client-example

Simple trivy client example code based on the [trivy go library](https://github.com/aquasecurity/trivy).

> Just an example and not suitable to use in production. 

## Usage

1. Launch a trivy server.

    ```console
    $ trivy server --listen=127.0.0.1:8888
    ```

1. Launch another terminal session to clone and build this project.

    ```console
    $ git clone git@github.com:STARRY-S/trivy-client-example.git && cd trivy-client-example/
    $ go build .
    ```

1. Connect to the trivy server and scan container image.

    ```console
    $ ./trivy-client-example -image 'docker.io/library/alpine' -server http://127.0.0.1:8888
    INFO[0016] {
    "Target": "docker.io/library/alpine (alpine 3.19.1)",
    "Class": "os-pkgs",
    "Type": "alpine"
    } 
    ...
    ```

## License

[Apache-2.0](LICENSE)
