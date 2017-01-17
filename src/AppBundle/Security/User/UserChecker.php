<?php

namespace AppBundle\Security\User;

use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class UserChecker implements UserCheckerInterface
{
    /**
     * {@inheritdoc}
     */
    public function checkPreAuth(UserInterface $user)
    {

    }

    /**
     * {@inheritdoc}
     */
    public function checkPostAuth(UserInterface $user)
    {

    }
}
