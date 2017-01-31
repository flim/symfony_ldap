<?php

/*
 * This file is part of the Symfony package.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AppBundle\Security\User;

use AppBundle\Entity\User;
use FOS\UserBundle\Doctrine\UserManager;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\LdapClientInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

/**
 * Class UserProvider
 *
 * @package AppBundle\Security\User
 */
class UserProvider implements UserProviderInterface
{
    private $userManager;
    private $ldap;
    private $baseDn;
    private $searchDn;
    private $searchPassword;
    private $defaultRoles;
    private $defaultSearch;

    /**
     * @param UserManager         $userManager
     * @param LdapClientInterface $ldap
     * @param string              $baseDn
     * @param string              $searchDn
     * @param string              $searchPassword
     * @param array               $defaultRoles
     * @param string              $uidKey
     * @param string              $filter
     */
    public function __construct(UserManager $userManager,
                                LdapClientInterface $ldap,
                                $baseDn,
                                $searchDn = null,
                                $searchPassword = null,
                                array $defaultRoles = [],
                                $uidKey = 'sAMAccountName',
                                $filter = '({uid_key}={username})')
    {
        $this->userManager = $userManager;
        $this->ldap = $ldap;
        $this->baseDn = $baseDn;
        $this->searchDn = $searchDn;
        $this->searchPassword = $searchPassword;
        $this->defaultRoles = $defaultRoles;
        $this->defaultSearch = str_replace('{uid_key}', $uidKey, $filter);
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        try {
            $this->ldap->bind($this->searchDn, $this->searchPassword);
            $username = $this->ldap->escape($username, '', LDAP_ESCAPE_FILTER);
            $query = str_replace('{username}', $username, $this->defaultSearch);
            $search = $this->ldap->find($this->baseDn, $query);

        } catch (ConnectionException $e) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username), 0, $e);
        }

        if (!$search) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username));
        }

        if ($search['count'] > 1) {
            throw new UsernameNotFoundException('More than one user found');
        }

        $fields = [
            'cn',
            'sn',
            'givenname',
            'dn',
            'displayname',
            'company',
            'samaccountname',
            'mail'
        ];
        $user = [];
        foreach($fields as $field) {
            $user[$field] = $search[0][$field][0];
        };
        return $this->loadUser($user['cn'], $user);
    }

    /**
     * @param $username
     * @param $user
     * @return User|\FOS\UserBundle\Model\UserInterface
     */
    public function loadUser($username, $user)
    {
        $roles = $this->defaultRoles;
        $userObject = $this->userManager->findUserByUsername($username);
        if (null == $userObject) {
            $userObject = new User($username, null, $roles);
            $userObject->setUsername($user['cn']);
            $userObject->setUsernameCanonical(strtolower($user['cn']));
            $userObject->setEmail($user['mail']);
            $userObject->setEmailCanonical(strtolower($user['mail']));
            $userObject->setRoles($roles);
            $userObject->setPassword(md5(uniqid($user['cn'])));
            $userObject->setEnabled(true);
        }

        return $userObject;
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        return $user;
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return $class === 'AppBundle\Entity\User';
    }
}
