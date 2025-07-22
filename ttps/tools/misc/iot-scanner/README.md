searches and returns detailed information about devices that are directly connected to the internet [IoT] (Smart TV\'s, Fridges, Webcams, Traffic Lights etc).

# Prerequisites
* shodan.io API Key

Get it [here](https://shodan.io)

# Getting started
```
$ podman build -t eye .
$ podman run -it --name eye eye
```

```
$ python3 ./eye.py --auth [your-shodan-api-key]
```

> *Your API key will be stored in a hidden .auth file*

# Optional Arguments
| Flag          | MetaVar|                 Usage|
| ------------- |:----------------------:|:---------:|
| <code>-a/--auth</code>  |  **API key**  |  *api authentication with a valid shodan.io api key.* |
| <code>-q/--query</code>  | **QUERY**    |  *search query*|
| <code>-i/--ip</code>  |  **IP**  |  *return information relating to the specified IP address*  |
| <code>-o/--output</code>      |   **FILENAME** |  *write output to a specified file (will not work with -r/--raw)*  |
| <code>-r/--raw</code>  |    |  *return output in raw json format (also returns more detailed information)*  |
| <code>-v/--verbose</code>  |    |  *enable verbosity*  |
| <code>-u/--update</code>  |    |  *fetch program's latest updates*  |
| <code>--version</code>  |    |  *show program's version number and exit* |


# Disclaimer
> *This tool was developed sorely for educational purposes and should not be used in environments without legal authorization.
Therefore, the author shall not be responsible for the damages that might be done with it.*

# LICENSE
![license](https://user-images.githubusercontent.com/74001397/137917929-2f2cdb0c-4d1d-4e4b-9f0d-e01589e027b5.png)

