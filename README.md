# Proyecto2025 – Honey Management Platform

**Autores:** Arthur Zambrano & Reyes Alberto  
**Versión:** 1.0.0  

---

## Descripción  
Honey Management Platform es una solución web integral para la **gestión de apiarios y producción apícola**. Permite:  
- Controlar y visualizar apiarios (alta, edición, listado).  
- Registrar cosechas y parámetros de calidad (humedad, acidez, HMF, etc.).  
- Administrar inventario de productos y lotes de miel.  
- Generar alertas automáticas por correo y SMS cuando algún parámetro supera umbrales críticos.  
- Producir reportes PDF/Excel de producción, calidad y ventas.  

---

##  Características principales  
1. **Autenticación y autorización**  
   - Registro, inicio de sesión y restablecimiento de contraseña.  
   - Roles: `admin`, `apiario`, `user` con acceso diferenciado.  
2. **Módulo Apiarios**  
   - CRUD de apiarios con ubicación y fotos.  
3. **Módulo Cosechas**  
   - Registro histórico de cosechas y volúmenes.  
4. **Control de calidad**  
   - Definición de estándares y alertas automáticas.  
5. **Gestión de productos**  
   - Inventario de lotes, precios y trazabilidad.  
6. **Notificaciones**  
   - Correo vía Nodemailer y SMS vía Twilio.  
7. **Reportes**  
   - Exportación a PDF y Excel con métricas clave.  

---

## Stack tecnológico  
| Capa         | Tecnología                       |
|--------------|----------------------------------|
| Backend      | Node.js 18 + Express 5           |
| Frontend     | EJS (Embedded JavaScript)        |
| Base de datos| MySQL 8                          |
| Almacenamiento | Multer (subida de imágenes)    |
| Autenticación| JWT, bcryptjs, express-session   |
| Notificaciones | Nodemailer, Twilio              |
| Configuración| dotenv                           |

---

## Instalación  

1. **Clonar repositorio**  
   ```bash
   git clone https://github.com/Miel202122/Proyecto2025.git
   cd Proyecto2025

Instalar dependencias
npm install
Configurar variables de entorno
•	Crea un archivo .env en la raíz con estos valores mínimos:
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=tu_password
DB_DATABASE=appmiel
JWT_SECRET=clave_secreta
SMTP_USER=tu_correo@mail.com
SMTP_PASS=tu_smtp_password
TWILIO_SID=tu_twilio_sid
TWILIO_TOKEN=tu_twilio_token

Ignorar dependencias
•	Asegúrate de que node_modules/ esté en .gitignore.

Iniciar servidor
Acceder desde navegador
•	URL de desarrollo: http://localhost:3000/

Crear usuario admin
•	Desde la base de datos o CLI, inserta un registro en la tabla users con rol admin.
Navegar por módulos
Inicia sesión y explora Apiarios, Cosechas, Calidad, Productos y Reportes.
Contribuciones
Haz fork del repositorio.

Crea una rama de feature:

•	git checkout -b feature/nombre-de-tu-feature
Realiza commits claros.
Abre un Pull Request describiendo tus cambios.
Licencia
Este proyecto se distribuye bajo licencia MIT. Consulta el archivo LICENSE para más detalles.
Más información
Documentación de API: /docs/api.md
Script de creación de tablas y relaciones: /database/schema.sql
Guía de estilo de código y convenciones: /CONTRIBUTING.md
Contactos:
•	Arthur Zambrano – arthur@example.com
•	Reyes Alberto – reyes@example.com
