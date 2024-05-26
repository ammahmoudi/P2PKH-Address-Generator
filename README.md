# P2PKH-Address-Generator

![cover](/images/cover.jpg)

This Python application is designed to generate Pay-to-PubKey-Hash (P2PKH) Bitcoin addresses with the ability to specify the second and third characters of the address. It includes a loop to generate both public and private keys, runs the address generation algorithm, and checks if the address meets the specified criteria.

## Features

- Generates P2PKH Bitcoin addresses.
- Allows customization of the second and third characters of the address.
- Implements the full address generation algorithm, including SHA-256 and RIPEMD-160 hashing, network byte addition, checksum calculation, and Base58 encoding.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

What things you need to install the software and how to install them:

```
Python 3.x
```

### Installing

A step by step series of examples that tell you how to get a development environment running:

First, clone the repository to your local machine:

```sh
git clone https://github.com/your-username/P2PKH-Address-Generator.git
```

Then, navigate to the cloned directory:

```sh
cd P2PKH-Address-Generator
```

Install the required packages:

```sh
pip install -r requirements.txt
```