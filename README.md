
<br />
<p align="center">
  <h3 align="center">C++ SGX-Login</h3>

  <p align="center">
    A library to secure your application authentication using Intel® Software Guard Extensions
    <br />
    <br />
    <a href="https://github.com/enclaive/sgx_login/issues">Report Bug</a>
    ·
    <a href="https://github.com/enclaive/sgx_login/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
        <li><a href="#problems">Problems</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contributing">Contributing</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

Authentication is a very critical part of an application. Moving this into a simple small severed enclave ensures that attackers are not able to compromise your application login.

### Built With

* [C++](https://www.cplusplus.com/)
* [Intel® SGX Software Guard Extensions](https://www.intel.com/content/www/us/en/architecture-and-technology/software-guard-extensions.html)


<!-- GETTING STARTED -->
## Getting Started

This application needs hardware that supports [Intel® Software Guard Extensions](https://www.intel.com/content/www/us/en/support/articles/000028173/processors/intel-core-processors.html).

### Prerequisites

Make sure you installed the following software on your machine.

- [git](https://github.com/git-guides/install-git)
- [Microsoft Visual Studio](https://visualstudio.microsoft.com/)
- [Intel® Software Guard Extensions](https://downloadcenter.intel.com/de/product/80895)

### Installation

1. Get access to the [enclaive/sgx_login](https://github.com/enclaive/sgx_login) repository.
2. Clone the repository.

```sh
git clone git@github.com:enclaive/sgx_login.git
```

3. Open `sgx-login.sln` in Microsoft Visual Studio.

### Problems

The Build Version has to be the latest installed version to run this project and has to be selected for every project. The user can easily right click on one project:          
```
Proprties -> General -> Windows SDK Version. 
```
The second problem could be solved by right click on one project: 
```
Properties -> Extended -> Character Set -> Use Multibyte Character
````
instead of Unicode. The other setup to set the project directories right is to go to the 
```
Properties -> Debugging -> Woring Directory: $(OutDir)
````
 for each project.


<!-- USAGE EXAMPLES -->
## Usage

The example sgx_login project is a console project where the user can be registered, logged in and logged out. Just start the project using the normal function in Visual Studio and the console will appear. If the user needs any help, just type `help` to get some information to use the app. The following commands can be used:

| Commands      | Description|
| ------------- |:-----------|
| help      | List all commands |
| register  | Register a user with username and password   |
| login     | User can be logged in with username and password  |
| logout    | User can be logged out with the username |
| verify    | Check if the username exists |

<!-- TL;DR -->
##TL;DR

The sgx_login is build with the Intel sgx enlave libary and sealing technology to save user information within the enclave permanently.

<!-- CONTRIBUTING -->
## Contributing

Leon, Jannes, Tom built this Intel SGX login project.

