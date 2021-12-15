# Log4JKongWAF
This plugin will mitigate CVE2021-44228 in Kong layer

# How to use it.
Use this plugin in as Kong Cluster Plugin

### In DBless mode.

```
apiVersion: configuration.konghq.com/v1
kind: KongPlugin
metadata:
  name: <object name>
  namespace: <object namespace>
  labels:
    global: "true"
config:             
  enabled: value
plugin: Log4jKongWaf
```
