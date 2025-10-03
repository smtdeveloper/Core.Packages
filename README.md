# Core.Packages

`Core.Packages`, .NET projelerinde tekrar kullanılabilir **çekirdek katman** paketlerini bir araya getirir.  
Amaç: **Clean Architecture** prensipleri doğrultusunda, ortak kullanılan altyapı servislerini ayrı bir paket olarak sunmak.

---

## 📂 Katmanlar

- **Core.Application**  
  - Application seviyesinde kullanılan temel yapılar  
  - Mediator Behaviors (Validation, Authorization, Caching, Logging)  
  - Business Rules (BusinessException, ValidationException)

- **Core.CrossCuttingConcerns**  
  - Loglama, Validasyon, Cache  
  - Global exception handling altyapısı

- **Core.Persistence**  
  - Generic Repository Pattern  
  - Paging, IQueryable extensions  
  - Unit of Work desteği

- **Core.Security**  
  - Authentication & Authorization (JWT)  
  - Hashing & Salting  
  - Token helper’lar

---

## 🚀 Özellikler

- **Katmanlı mimari** desteği  
- **Generic Repository** & LINQ destekli data erişimi  
- **Custom Exception** yapıları  
- **Pipeline Behaviors**: Validation, Caching, Authorization  
- **Security**: Hashing, JWT auth  
- **Cross-cutting**: Logging, Transactions  

---

## 🔧 Kullanım

1. Core.Packages’ı solution’a ekle:
   ```bash
   dotnet add <YourProject> reference Core.Packages/Core.Packages.csproj
