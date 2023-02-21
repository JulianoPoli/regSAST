# regSAST
Regex-based vulnerability scanning

##### Features

- Simple implementation of new regex
- Scan all files type
- JSON Report (dev)

### How Use

```sh
git clone https://github.com/JulianoPoli/regSAST.git
python3 regSast.py {SCAN_DIR}

Exemple: python3 regSast.py myProject/src
```

### Bypass formats

É possível ignorar arquivos por sua extensão. Para isso, basta adicionar o formato que deseja ignorar no array BYPASS_EXT
```sh
#Ignore file types
BYPASS_EXT = ["jpg","png","xml","gitignore","pdf", "js", "yml"]
```