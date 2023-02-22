# regSAST
Regex-based vulnerability scanning

##### Features

- Simple implementation of new regex
- Scan all files type
- JSON Report

### How Use

```sh
git clone https://github.com/JulianoPoli/regSAST.git
python3 regSast.py {SCAN_DIR}

Exemple: python3 regSast.py myProject/src
```

### Bypass formats

It is possible to ignore files by their extension. For that, just add the format you want to ignore in the BYPASS_EXT array
```sh
#Ignore file types
BYPASS_EXT = ["jpg","png","xml","gitignore","pdf", "js", "yml"]
```