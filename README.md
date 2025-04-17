# Mandiant Intelligence to Suricata Intelligence

> It is `under development`, so if something breaks in your production Suricata is your fault/responsibility. You have been warned !!!

## Purpose

Download Mandiant Intelligence though Mandiant's API and convert it 
to Suricata datasets/datareps.

- Creates datasets/datareps ready to be consumed by Suricata through Suricata Rules
- Lua Script that checks the whole URL and creates alerts to different log file

Be aware that Mandiant Intelligence has IOCs like `https://www.youtube.com/c?sfksdflsdfjsldfj` and 
you have to have unencrypted traffic in order to detect it. Hence if you don't decrypt TLS traffic, you have to rely on TLS SNI.

In order to avoid false positives, I don't load these IOCs as hostnames.  Whilelisting it is mandatory for these IOCs (future work).

There are also some IOCs which begin with `smtp://` ,  `tcp://` ... For those I extract the hostname and put it in `fqdn.lst`

`smtp.helo` sticky buffer will be available on Suricata 8.0, so till then ...


## Known Issues

When I use datareps I cannot load more than 241000 records even if I 
change the `memcap` and `hashsize` values. By using datasets I am not
facing this issue. Maybe I do something wrong ...

Actually Suricata in `suricata.log` says that all the records have been loaded, but if the IOC is below line ~241000 it never triggers. Maybe a timeout take place.

## Dependencies

- Mandiant's API Client ( https://github.com/google/mandiant-ti-client )

## Execution

```
python3 main.py -h
```

After a successful execution it will create in the same folder
the lists that you have to configure in the `suricata.yaml`

## Configuration

### Config.ini
Create a `config.ini` in the same folder with format

```
[MANDIANT_CONFIG]
api_key = <api_key> 
secret_key = <secret_key>
```


### suricata.yaml

```
datasets:
  # Default fallback memcap and hashsize values for datasets in case these
  # were not explicitly defined.
  defaults:
    #memcap: 100mb
    #hashsize: 2048
  fqdn:
    type: string
    load: /home/christos/gitrepos/mandiant_to_suricata_datasets/fqdn.lst
    memcap: 150mb
  ipv4:
    type: string
    load: /home/christos/gitrepos/mandiant_to_suricata_datasets/ipv4.lst
    memcap: 150mb
    ...
```

```
  - lua:
      enabled: yes
      #scripts-dir: /etc/suricata/lua-output/
      scripts:
        - /home/christos/gitrepos/mandiant_to_suricata_datasets/http-threatintel.lua
```

Additional configuration inside `lua` script file.

### Suricata Rules


These are example rules

```
alert tls any any -> any any (msg:"Mandiant Intelligence - Malicious TLS SNI Detected";tls.sni; datarep:fqdn, >, 80; sid:3;)
alert http any any -> any any (msg:"Mandiant Intelligence - Malicious HTTP SNI Detected";http.host; datarep:fqdn, >, 80; sid:4;)
alert dns any any -> any any (msg:"Mandiant Intelligence - Malicious DNS Query Detected";dns.query; datarep:fqdn, >, 80; sid:5;)
alert ip any any -> any any (msg:"Mandiant Intelligence - Malicious DNS Query Detected";ip.dst; datarep:ipv4, >, 80; sid:6;)
```



