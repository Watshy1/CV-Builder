<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

use App\Entity\User;
use Doctrine\Persistence\ManagerRegistry;

class HomeController extends AbstractController
{
    #[Route('/', name: 'app_home')]
    public function index(Request $request): Response
    {
        $session = $request->getSession();
        $userSession = $session->get('user');

        return $this->render('home/index.html.twig', [
            'user' => $userSession
        ]);
    }

    #[Route('/register', name: 'app_register')]
    public function register(ManagerRegistry $doctrine): Response
    {
        $entityManager = $doctrine->getManager();

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $firstname = $_POST['firstname'];
            $lastname = $_POST['lastname'];
            $email = $_POST['email'];
            $password = $_POST['password'];
            $passwordVerif = $_POST['passwordVerif'];

            if (isset($firstname) && isset($lastname) && isset($email) && isset($password) && isset($passwordVerif) && $password == $passwordVerif) {
                $user = new User();
                $user->setFirstname($firstname);
                $user->setLastname($lastname);
                $user->setEmail($email);
                $user->setPassword(password_hash($password, PASSWORD_BCRYPT));

                $entityManager->persist($user);
                $entityManager->flush();

                return $this->redirectToRoute('app_login');
            }
        }

        return $this->render('home/register.html.twig');
    }

    #[Route('/login', name: 'app_login')]
    public function login(ManagerRegistry $doctrine, Request $request): Response
    {
        $session = $request->getSession();

        $entityManager = $doctrine->getManager();
        $userRepository = $entityManager->getRepository(User::class);

        if ($_SERVER['REQUEST_METHOD'] == 'POST') {
            $email = $_POST['email'];
            $password = $_POST['password'];

            if (isset($email) && isset($password)) {
                $user = $userRepository->findOneBy(['email' => $email]);

                if ($user) {
                    if (password_verify($password, $user->getPassword())) {
                        $session->set('user', $user);

                        return $this->redirectToRoute('app_home');
                    }
                }
            }
        }

        return $this->render('home/login.html.twig');
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(Request $request): Response
    {
        $session = $request->getSession();
        $session->remove('user');

        return $this->redirectToRoute('app_home');
    }
}
