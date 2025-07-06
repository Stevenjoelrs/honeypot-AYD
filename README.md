<div align="center">

# Honeypot SSH en Python

![Python](https://img.shields.io/badge/python-3.9-blue.svg?style=for-the-badge&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)

Un honeypot SSH de baja interacción, desarrollado desde cero para simular un servidor Arch Linux, capturar credenciales y registrar la actividad de los atacantes en un entorno seguro y aislado con Docker.

</div>

---

## Tabla de Contenidos

* [Acerca del Proyecto](#acerca-del-proyecto)
* [Características](#características)
* [Empezando con Docker](#empezando-con-docker)
  * [Prerrequisitos](#prerrequisitos)
  * [Instalación y Ejecución](#instalación-y-ejecución)
* [Advertencia de Seguridad](#advertencia-de-seguridad)

---

## Acerca del Proyecto

Este proyecto nació como un mini proyecto práctico para comprender a fondo el protocolo SSH, las técnicas de los atacantes y los fundamentos de la seguridad defensiva. En lugar de utilizar herramientas preexistentes, el honeypot se construyó desde cero utilizando Python y la librería `paramiko`, ofreciendo una visión clara de la lógica.

La aplicación está diseñada para ser ligera, fácil de desplegar y, sobre todo, segura gracias a su encapsulación en un contenedor Docker.

**Construido con:**
* [Python](https://www.python.org/)
* [Paramiko](https://www.paramiko.org/)
* [Docker](https://www.docker.com/)

---

## Características

* **Simulación**: Imita un servidor Arch Linux, respondiendo a comandos comunes como `ls`, `ps aux`, `uname -a`, `netstat`, `id`, `w`, y `free`.
* **Captura de Datos**: Registra cada intento de conexión, par de credenciales (usuario/contraseña) y todos los comandos ejecutados en `honeypot.log`.
* **Aislamiento Seguro**: Se ejecuta completamente dentro de un contenedor Docker, protegiendo el sistema anfitrión.
* **Despliegue Sencillo**: Se levanta con unos pocos comandos de Docker, sin necesidad de configurar un entorno de Python localmente.
* **Baja Interacción**: Proporciona un entorno seguro que no puede ser comprometido para atacar otros sistemas.

---

## Empezando con Docker

La forma recomendada y más segura de ejecutar este honeypot es a través de Docker.

### Prerrequisitos

Asegúrese de tener **Docker** instalado y funcionando en su sistema.
* [Instrucciones de instalación de Docker](https://docs.docker.com/engine/install/)

### Instalación y Ejecución

1.  **Clone este repositorio:**
    ```bash
    git clone https://github.com/Stevenjoelrs/honeypot-AYD.git
    cd honeypot-AYD
    ```

2.  **Construya la imagen de Docker:**
    ```bash
    docker build -t ssh-honeypot .
    ```

3.  **Inicie el contenedor del honeypot:**
    ```bash
    docker run --rm -it -p 2222:2222 --name mi-honeypot proyecto-honeypot
    ```
    Su honeypot ya está activo y escuchando en el puerto `2222`.

4.  **Pruebe la conexión y vea los logs:**
    * Para conectarse (use cualquier contraseña):
        ```bash
        ssh usuario-falso@localhost -p 2222
        ```
    * Para ver los logs en tiempo real:
        ```bash
        docker exec mi-honeypot tail -f honeypot.log
        ```

5.  **Para detener el contenedor:**
    ```bash
    docker stop mi-honeypot && docker rm mi-honeypot
    ```

---

## ⚠️ Advertencia de Seguridad

Este software está diseñado para ser atacado. **Nunca lo despliegue en una red de producción o en un sistema que contenga información sensible.** Úselo únicamente en un entorno de red aislado para fines de investigación.

---

