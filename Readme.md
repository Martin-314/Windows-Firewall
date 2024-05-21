# Windows firewall Utility.

 ![Static Badge](https://img.shields.io/badge/Python-v3.11-blue)   ![Static Badge](https://img.shields.io/badge/Platform-Windows-blue) 


This is a simple tool created using python that gives the windows `netsh advfirewall firewall` command a user interface.
Think of it as 

## Dependencies
- [flet](https://flet.dev/)
- [ipaddress](https://docs.python.org/3/library/ipaddress.html)
- [subprocess](https://docs.python.org/3/library/subprocess.html)
- [os](https://docs.python.org/3/library/os.html)

## Usage and Installation
No installation is required for this tool. Just download the portable executable and run it. 

### Or 
Run the script directly using python.

```commandline
py main.py
```
### Adding firewall rule.

#### 1. One rule at a time.
Clicking the desired chip will display the parameters required to set a firewall rule.

#### 2. Multiple.
To create a rule for multiple ip addresses create a text file with each address on a new line, for example.
```commandline
1.1.1.1
192.168.1.1
2.2.2.2
10.10.10.10
127.0.0.1
```
##### Note
All addresses in the list should have the same set of actions to be taken against them i.e. A text file can
have a list of local ip addresses from which all outbound traffic will be blocked. 

## Packaging 
#### 1. Using auto-py-to-exe
Auto-py-to-exe installation.
```commandline
py -m pip install auto-py-to-exe
```
Then to run.

```commandline
auto-py-to-exe
```

#### 2. Using Flet (recommended).
This is the preferred way of packaging your application created with [flet](https://flet.dev/).
```commandline
flet pack main.py --product-name name --product-version 1.0 --name "name" --icon "asserts\file.ico"
```
## Preview.
![Alt](/previews/preview.png)



