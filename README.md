
![image](https://github.com/chadow4/Symfony-JWT-Docs/assets/73313152/b2ad4dd7-fa08-4659-8565-525f1b87ccb1)

# Symfony-JWT-Docs

Little Documentation to learn JWT in Symfony 7

## Etape 1 : Création d'un projet

```
composer create-project symfony/skeleton myproject
```

## Etape 2 : Installation des différents packages

```
composer require jms/serializer-bundle
composer require symfony/maker-bundle
composer require symfony/orm-pack --with-all-dependencies
composer require lexik/jwt-authentication-bundle:*
```
## Etape 3 : Configuration Database Configuration 
.env
```yml

# In all environments, the following files are loaded if they exist,
# the latter taking precedence over the former:
#
#  * .env                contains default values for the environment variables needed by the app
#  * .env.local          uncommitted file with local overrides
#  * .env.$APP_ENV       committed environment-specific defaults
#  * .env.$APP_ENV.local uncommitted environment-specific overrides
#
# Real environment variables win over .env files.
#
# DO NOT DEFINE PRODUCTION SECRETS IN THIS FILE NOR IN ANY OTHER COMMITTED FILES.
# https://symfony.com/doc/current/configuration/secrets.html
#
# Run "composer dump-env prod" to compile .env files for production use (requires symfony/flex >=1.2).
# https://symfony.com/doc/current/best_practices.html#use-environment-variables-for-infrastructure-configuration

###> symfony/framework-bundle ###
APP_ENV=dev
APP_SECRET=1ca70aef937fe5cd41cb03a18db50e04
###< symfony/framework-bundle ###

###> doctrine/doctrine-bundle ###
# Format described at https://www.doctrine-project.org/projects/doctrine-dbal/en/latest/reference/configuration.html#connecting-using-a-url
# IMPORTANT: You MUST configure your server version, either here or in config/packages/doctrine.yaml
#
# DATABASE_URL="sqlite:///%kernel.project_dir%/var/data.db"
DATABASE_URL="mysql://!userDb:!passwordDb@127.0.0.1:3306/!nom_database?serverVersion=8.0.32&charset=utf8mb4"
# DATABASE_URL="mysql://app:!ChangeMe!@127.0.0.1:3306/app?serverVersion=10.11.2-MariaDB&charset=utf8mb4"
# DATABASE_URL="postgresql://app:!ChangeMe!@127.0.0.1:5432/app?serverVersion=16&charset=utf8"
###< doctrine/doctrine-bundle ###
```

```
php bin/console doctrine:database:create
```

## Etape 4 : Creation de la classe User

```
php bin/console make:user
```       

```
 The name of the security user class (e.g. User) [User]:
 >
  
 Do you want to store user data in the database (via Doctrine)? (yes/no) [yes]:
 >
  
 Enter a property name that will be the unique "display" name for the user (e.g. email, username, uuid) [email]:
 >
  
 Will this app need to hash/check user passwords? Choose No if passwords are not needed or will be checked/hashed by some other system (e.g. a single sign-on server).
  
 Does this app need to hash/check user passwords? (yes/no) [yes]:
 >
  
 created: src/Entity/User.php
 created: src/Repository/UserRepository.php
 updated: src/Entity/User.php
 updated: config/packages/security.yaml
  
   
  Success! 
   
  
 Next Steps:
   - Review your new App\Entity\User class.
   - Use make:entity to add more fields to your User entity and then run make:migration.
   - Create a way to authenticate! See https://symfony.com/doc/current/security.html

```

## Etape 5 : Creation de la migration

création de la migration
```
php bin/console make:migration
```
lancement de la migration pour mettre à jour la base de données
```
php bin/console doctrine:migrations:migrate
```

## Etape 6 : Configuration JWT Bundle
```
php bin/console lexik:jwt:generate-keypair
```

dans le fichier config/routes.yaml ajouter : 
```yml
api_login_check:
    path: /api/login_check
```

## Etape 7 : Création des controllers RegistrationController et Dashboard

Nous allons dabord créer le RegistrationController

```
php bin/console make:controller RegistrationController
```
src/Controller/RegistrationController.php
```php
<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/api', name: 'api_')]
class RegistrationController extends AbstractController
{
    #[Route('/register', name: 'register', methods: 'post')]
    public function index(EntityManagerInterface $em, UserRepository $userRepository, Request $request, UserPasswordHasherInterface $passwordHasher): JsonResponse
    {
        $decoded = json_decode($request->getContent(), true);

        if (!$decoded || !isset($decoded['email'], $decoded['password'])) {
            throw new HttpException(400, 'Invalid data');
        }

        $email = $decoded['email'];
        $plaintextPassword = $decoded['password'];

        // Vérifier si l'utilisateur existe déjà
        if ($userRepository->findOneBy(['email' => $email])) {
            throw new HttpException(409, 'User already exists');
        }

        $user = new User();
        $hashedPassword = $passwordHasher->hashPassword($user, $plaintextPassword);

        $user->setPassword($hashedPassword);
        $user->setEmail($email);
        $user->setRoles(['ROLE_USER']);

        $em->persist($user);
        $em->flush();

        return $this->json(['message' => 'Registered Successfully']);
    }
}
```
Maintenant nous allons créer le DashboardController qui récuperera les informations de l'utilisateur connecté et nous allons par exemple pouvoir donner l'accès qu'au role admin

```
php bin/console make:controller DashboardController
```
src/Controller/DashboardController.php 
```php
<?php

namespace App\Controller;

use App\Repository\UserRepository;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;

#[Route('/api', name: 'api_')]
class DashboardController extends AbstractController
{
    #[Route('/dashboard', name: 'app_dashboard',methods: 'get')]
    #[IsGranted('ROLE_ADMIN', message: 'Access denied')]
    public function index(TokenStorageInterface $tokenStorage, UserRepository $userRepository): JsonResponse
    {
        $userIdentifier = $tokenStorage->getToken()->getUserIdentifier();

        $user = $userRepository->findOneBy(['email' => $userIdentifier]);

        return $this->json([
            'id' => $user->getId(),
            'user' => $user->getEmail(),
            'roles' => $user->getRoles(),
        ]);
    }
}
```
## Etape 8 : Configuration Security.yaml 

Lors de cette configuration nous allons dire que les routes /api/register et /api/login sont en public_access tandis que toute les autres routes /api sont accessible qu'en étant connecté

config/package/security.yaml 

```yml
security:
    password_hashers:
        App\Entity\User: 'auto'
        Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface:
            algorithm: 'auto'
            cost:      15
    providers:
        app_user_provider:
            entity:
                class: App\Entity\User
                property: email
    firewalls:
        login:
            pattern: ^/api/login
            stateless: true
            json_login:
                check_path: /api/login_check
                username_path: email
                password_path: password
                success_handler: lexik_jwt_authentication.handler.authentication_success
                failure_handler: lexik_jwt_authentication.handler.authentication_failure

        api:
            pattern:   ^/api
            stateless: true
            jwt: ~
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: true
            provider: app_user_provider

    access_control:
        - { path: ^/api/register, roles: PUBLIC_ACCESS  }
        - { path: ^/api/login, roles: PUBLIC_ACCESS  }
        - { path: ^/api,       roles: IS_AUTHENTICATED_FULLY }

```

### Etape 9 : Lancer le serveur 

```bash
symfony server:start
```

### Etape 10 : Test des Endpoints

 **Inscription** (`/api/register`) : Permet aux utilisateurs de s'inscrire.

![image](https://github.com/chadow4/Symfony-JWT-Docs/assets/73313152/1bf8b0f5-c9c0-4ce2-8c10-4bdaad8a9d7b)

**Connexion** (`/api/login_check`) : Authentifie les utilisateurs et retourne un JWT.

![image](https://github.com/chadow4/Symfony-JWT-Docs/assets/73313152/d7f262aa-23b5-40ae-86a1-32d9984182e5)

 **Dashboard** (`/api/dashboard`) :

 - Sans authentification : Erreur 401.

![image](https://github.com/chadow4/Symfony-JWT-Docs/assets/73313152/a51161b5-cb08-442d-9e25-9fcdb1279dbe)

 - Authentification sans rôle admin : Erreur 403.

![image](https://github.com/chadow4/Symfony-JWT-Docs/assets/73313152/6a7966bd-de0c-4773-a57f-b7cb358be183)


 - Authentification avec rôle admin : Accès au dashboard et récupération des données.

![image](https://github.com/chadow4/Symfony-JWT-Docs/assets/73313152/a3cce982-b4e8-4130-8fa9-646b23f71f72)


