## Wallarm gotestwaf

[github](https://github.com/wallarm/gotestwaf)

https://lab.wallarm.com/test-your-waf-before-hackers/

```sh

sudo podman build -t gotestwaf .

mkdir -p ${PWD}/reports

sudo podman run --rm -it --network=host -v ${PWD}/reports:/app/reports \
           gotestwaf --url=<EVALUATED_SECURITY_SOLUTION_URL> --noEmailReport

```

