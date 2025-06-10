# AuthGuard

A secure, token-based authentication and authorization API built with ASP.NET Core. Includes JWT authentication, email-based user verification, and SQL Server integration.

---

## 📝 Project Overview

### 📋 Key Features

---

## ⚙️ Technologies Used

- ASP.NET Core Web API
- Entity Framework Core
- SQL Server
- JWT Authentication
- SMTP (Gmail/Other)

---

## 🚀 Getting Started

### Prerequisites

* .NET 8 SDK
* SQL Server
* Visual Studio 2022 (or later)

### Installation

1. Clone the repository:

   ```bash
   https://github.com/Nirob-Barman/AuthGuard.git
   cd AuthGuard
   ```
2. Configure the database connection in **appsettings.json**.
3. Run database migrations:

   ```bash
   dotnet ef database update
   ```
4. Build and run the project:

   ```bash
   dotnet run
   ```
5. Open the project in your browser:

   ```
   https://localhost:5000
   ```

### Database Setup

Ensure the **DefaultConnection** string in **appsettings.json** is correctly configured for your SQL Server instance:

```json
"ConnectionStrings": {
  "DefaultConnection": "Server=localhost;Database=AuthGuard;Trusted_Connection=True;MultipleActiveResultSets=true"
}
```

## 🔐 JWT Settings

These values are used for authentication and token issuance.

```
"JwtSettings": {
  "Key": "your-very-secure-key",
  "Issuer": "http://localhost:5000",
  "Audience": "http://localhost:5000",
  "ExpiryMinutes": 60
}
```

## ✉️ Email Configuration (SMTP)
To enable email features such as registration confirmations, password resets, or orher notifications, you must configure SMTP settings in your appsettings.json:
```
"EmailSettings": {
  "SmtpServer": "smtp.example.com",
  "Port": 587,
  "SenderName": "AuthGuard",
  "SenderEmail": "noreply@AuthGuard.com",
  "Username": "your-smtp-username",
  "Password": "your-smtp-password",
  "EnableSsl": true
}
```

---

## 📂 Project Structure

```

```

---

## 🔧 Key Components

### Models


### Controllers

---

## 🤝 Contribution Guidelines

* Fork the repository.
* Create a feature branch.
* Commit your changes.
* Push to the branch.
* Open a pull request.

---

## 📅 Future Improvements

---

## 📞 Support

For support, please open an issue or reach out via [nirob.barman.19@gmail.com](mailto:nirob.barman.19@gmail.com).

---

## ✍️ Author

- 👤 **Nirob Barman**  
- [![Medium](https://img.shields.io/badge/Medium-Blog-black?logo=medium)](https://nirob-barman.medium.com/)
- [![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://www.linkedin.com/in/nirob-barman/)
- [![Portfolio](https://img.shields.io/badge/Portfolio-Visit-brightgreen?logo=firefox-browser)](https://nirob-barman-19.web.app/)
- [![Email](https://img.shields.io/badge/Email-Contact-orange?logo=gmail)](mailto:nirob.barman.19@gmail.com)

---

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.
