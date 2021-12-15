# Log4JKongWAF
This plugin will mitigate CVE2021-44228 in Kong layer

ref nginx plugin: https://github.com/tippexs/nginx-njs-waf-cve2021-44228 
# How to use it.
Use this plugin as Kong Cluster Plugin

### In DBless mode.

```
apiVersion: configuration.konghq.com/v1
kind: KongClusterPlugin
metadata:
  name: <object name>
  namespace: <object namespace>
  labels:
    global: "true"
config:             
  enabled: value
plugin: Log4jKongWaf
```
