# Sistema de Cifrado de Texto con Persistencia y Autenticación

Este proyecto consiste en una aplicación web integral diseñada para cifrar, almacenar y recuperar texto mediante tokens únicos. La arquitectura está basada en microservicios utilizando Docker para garantizar la portabilidad y persistencia de los datos.

## Arquitectura del Sistema
- **Frontend:** Interfaz estática desarrollada en HTML5, JavaScript (ES6) y Bootstrap 5.
- **Backend:** API REST construida con Python 3.11 y el framework Flask.
- **Base de Datos:** PostgreSQL 15 (Imagen Alpine) para almacenamiento relacional.
- **Seguridad:** Cifrado simétrico AES mediante la librería Cryptography (Fernet) y hashing de contraseñas con Werkzeug.

## Estructura del Repositorio
- `/backend`: Código fuente de la API, modelos de base de datos y configuración de entorno.
- `/frontend`: Interfaz de usuario y lógica de consumo de API.
- `docker-compose.yml`: Archivo de orquestación de servicios.

## Requisitos Previos
- Docker Desktop instalado.
- Navegador web moderno (Chrome, Edge o Firefox).

## Instrucciones de Instalación y Despliegue

1. Clone el repositorio o descargue los archivos del proyecto.
2. Abra una terminal en la raíz de la carpeta del proyecto.
3. Ejecute el comando para construir e iniciar los contenedores:
   ```bash
   docker compose up --build
4. Verifique que los contenedores flask_backend_container y secure_db_container se encuentren en estado "Running".   
    ✔ Container api_tarea3_analisis  
    ✔ Container db_tarea3_analisis  

5. Para visualizar el sistema debe de arrastrar el index a cualquier ventana del navegador de su preferencia
   