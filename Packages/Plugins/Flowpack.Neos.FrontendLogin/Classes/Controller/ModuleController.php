<?php
declare(strict_types=1);

namespace Flowpack\Neos\FrontendLogin\Controller;

/*
 * This file is part of the Flowpack.Neos.FrontendLogin package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\Error\Messages\Message;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Exception\UnsupportedRequestTypeException;
use Neos\Flow\Persistence\Exception\IllegalObjectTypeException;
use Neos\Flow\Security\Account;
use Neos\Flow\Security\AccountRepository;
use Neos\Flow\Security\Policy\PolicyService;
use Neos\Flow\Security\Policy\Role;
use Neos\Neos\Controller\Module\AbstractModuleController;
use Neos\Neos\Domain\Exception as NeosDomainException;
use Neos\Neos\Domain\Model\User;
use Neos\Neos\Domain\Service\UserService;

/**
 * @Flow\Scope("singleton")
 */
class ModuleController extends AbstractModuleController
{
    /**
     * @Flow\Inject
     * @var UserService
     */
    protected $userService;

    /**
     * @Flow\Inject
     * @var PolicyService
     */
    protected $policyService;

    /**
     * @Flow\Inject
     * @var AccountRepository
     */
    protected $accountRepository;

    /**
     * @var User
     */
    protected $currentUser;

    /**
     * @var string
     */
    static protected $authenticationProviderName = 'Flowpack.Neos.FrontendLogin:Frontend';

    /**
     * @var string
     */
    static protected $roleIdentifier = 'Flowpack.Neos.FrontendLogin:User';

    /**
     * @return void
     */
    protected function initializeAction()
    {
        parent::initializeAction();
        $this->currentUser = $this->userService->getCurrentUser();
    }

    /**
     * Renders a list of frontend users and allows modifying them.
     */
    public function indexAction(): void
    {
        $this->view->assign('users', $this->findFrontendUsers());
    }

    /**
     * Shows details for the specified user
     *
     * @param User $user
     * @return void
     * @throws UnsupportedRequestTypeException
     */
    public function showAction(User $user): void
    {
        if ($this->checkUser($user)) {
            $this->view->assignMultiple([
                'currentUser' => $this->currentUser,
                'user' => $user,
                'expirationDate' => $user->getAccounts()->first()->getExpirationDate()
            ]);
        } else {
            $this->throwStatus(403, 'Not allowed to show that user');
        }
    }

    /**
     * Renders a form for creating a new user
     *
     * @return void
     */
    public function newAction(): void
    {
        $this->view->assignMultiple([
            'currentUser' => $this->currentUser,
            'availableRoles' => $this->getFrontendUserRoles()
        ]);
    }

    /**
     * Create a new user
     *
     * @param string $username The user name (ie. account identifier) of the new user
     * @param array $password Expects an array in the format array('<password>', '<password confirmation>')
     * @param User $user The user to create
     * @param \DateTime|null $expirationDate
     * @param array $roleIdentifiers Identifiers of roles to assign to account
     * @return void
     * @Flow\Validate(argumentName="username", type="\Neos\Flow\Validation\Validator\NotEmptyValidator")
     * @Flow\Validate(argumentName="username", type="\Neos\Neos\Validation\Validator\UserDoesNotExistValidator")
     * @Flow\Validate(argumentName="password", type="\Neos\Neos\Validation\Validator\PasswordValidator", options={ "allowEmpty"=0, "minimum"=1, "maximum"=255 })
     */
    public function createAction(string $username, array $password, User $user, ?\DateTime $expirationDate, array $roleIdentifiers = []): void
    {
        // make sure self::$roleIdentifier is always added
        $roleIdentifiersToSet = array_unique(array_merge($roleIdentifiers, [self::$roleIdentifier]));
        if ($this->onlyFrontendRoles($roleIdentifiersToSet)) {
            $user = $this->userService->addUser($username, $password[0], $user, $roleIdentifiersToSet, self::$authenticationProviderName);

            if ($expirationDate !== null) {
                /** @var Account $account */
                $account = $user->getAccounts()->first();
                $expirationDate->setTime(0, 0);
                $account->setExpirationDate($expirationDate);
            }

            $this->addFlashMessage('The user "%s" has been created.', 'User created', Message::SEVERITY_OK, [htmlspecialchars($username)], 1416225561);
        } else {
            $this->throwStatus(403, 'Not allowed to assign the given roles');
        }
        $this->redirect('index');
    }

    /**
     * Edit an existing user
     *
     * @param User $user
     * @return void
     * @throws UnsupportedRequestTypeException
     */
    public function editAction(User $user): void
    {
        if ($this->checkUser($user)) {
            $this->view->assignMultiple([
                'currentUser' => $this->currentUser,
                'user' => $user
            ]);
        } else {
            $this->throwStatus(403, 'Not allowed to edit that user');
        }
    }

    /**
     * Update a given user
     *
     * @param User $user The user to update, including updated data already (name, email address etc)
     * @return void
     * @throws UnsupportedRequestTypeException
     */
    public function updateAction(User $user): void
    {
        if ($this->checkUser($user)) {
            $this->userService->updateUser($user);
            $this->addFlashMessage('The user "%s" has been updated.', 'User updated', Message::SEVERITY_OK, [$user->getName()->getFullName()], 1412374498);
            $this->redirect('index');
        } else {
            $this->throwStatus(403, 'Not allowed to update that user');
        }
    }

    /**
     * Delete the given user
     *
     * @param User $user
     * @return void
     * @throws NeosDomainException
     * @throws UnsupportedRequestTypeException
     */
    public function deleteAction(User $user): void
    {
        if ($user === $this->currentUser) {
            $this->addFlashMessage('You can not delete the currently logged in user', 'Current user can\'t be deleted', Message::SEVERITY_WARNING, [], 1412374546);
            $this->redirect('index');
        }

        if ($this->checkUser($user)) {
            $this->userService->deleteUser($user);
            $this->addFlashMessage('The user "%s" has been deleted.', 'User deleted', Message::SEVERITY_NOTICE, [htmlspecialchars($user->getName()->getFullName())], 1412374546);
            $this->redirect('index');
        } else {
            $this->throwStatus(403, 'Not allowed to delete that user');
        }
    }

    /**
     * Edit the given account
     *
     * @param Account $account
     * @return void
     * @throws NeosDomainException
     * @throws UnsupportedRequestTypeException
     */
    public function editAccountAction(Account $account): void
    {
        if ($this->checkAccount($account)) {
            $this->view->assignMultiple([
                'account' => $account,
                'user' => $this->userService->getUser($account->getAccountIdentifier(), $account->getAuthenticationProviderName()),
                'expirationDate' => $account->getExpirationDate(),
                'availableRoles' => $this->getFrontendUserRoles()
            ]);
        } else {
            $this->throwStatus(403, 'Not allowed to edit that account');
        }
    }

    /**
     * Update a given account
     *
     * @param Account $account The account to update
     * @param array $roleIdentifiers Identifiers of roles to assign to account
     * @param array $password Expects an array in the format array('<password>', '<password confirmation>')
     * @Flow\Validate(argumentName="password", type="\Neos\Neos\Validation\Validator\PasswordValidator", options={ "allowEmpty"=1, "minimum"=1, "maximum"=255 })
     * @return void
     * @throws NeosDomainException
     * @throws IllegalObjectTypeException
     * @throws UnsupportedRequestTypeException
     */
    public function updateAccountAction(Account $account, array $roleIdentifiers = [], array $password = []): void
    {
        if ($this->checkAccount($account)) {
            // make sure self::$roleIdentifier is always added
            $roleIdentifiersToSet = array_unique(array_merge($roleIdentifiers, [self::$roleIdentifier]));

            if ($this->onlyFrontendRoles($roleIdentifiersToSet)) {
                // add any non-FE roles from the current roles to keep them unchanged
                $roleIdentifiersToSet = $this->addExistingNonFrontendUserRoles($roleIdentifiersToSet, $account);

                $this->userService->setRolesForAccount($account, $roleIdentifiersToSet);
                $user = $this->userService->getUser($account->getAccountIdentifier(), $account->getAuthenticationProviderName());
                $password = array_shift($password);
                if (trim((string)$password) !== '') {
                    $this->userService->setUserPassword($user, $password);
                }
                $this->accountRepository->update($account);

                $this->addFlashMessage('The account has been updated.', 'Account updated');
                $this->redirect('edit', null, null, ['user' => $user]);
            } else {
                $this->throwStatus(403, 'Not allowed to assign the given roles');
            }
        } else {
            $this->throwStatus(403, 'Not allowed to update that account');
        }
    }

    /**
     * Returns all "frontend users", i.e. those having exactly one account with self::$authenticationProviderName
     * and at least the role self::$roleIdentifier.
     *
     * @return User[]
     */
    protected function findFrontendUsers(): array
    {
        return array_filter($this->userService->getUsers()->toArray(), [$this, 'checkUser']);
    }

    /**
     * Returns true if the given user is a "frontend users", i.e. has exactly one account with self::$authenticationProviderName
     * and at least the role self::$roleIdentifier.
     *
     * @param User $user
     * @return bool
     */
    protected function checkUser(User $user): bool
    {
        $accounts = $user->getAccounts();
        if (count($accounts) === 1) {
            /** @var Account $account */
            $account = $accounts->first();
            return $this->checkAccount($account);
        }

        return false;
    }

    /**
     * Returns true if the given user is a "frontend users", i.e. has exactly one account with self::$authenticationProviderName
     * and at least the role self::$roleIdentifier.
     *
     * @param Account $account
     * @return bool
     */
    protected function checkAccount(Account $account): bool
    {
        if ($account->getAuthenticationProviderName() === self::$authenticationProviderName) {
            foreach ($account->getRoles() as $role) {
                if ($role->getIdentifier() === self::$roleIdentifier) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Returns all roles that are (indirect) heirs of self::$roleIdentifier
     *
     * @return Role[] indexed by role identifier
     */
    protected function getFrontendUserRoles(): array
    {
        $availableRoles = $this->policyService->getRoles();
        return array_filter($availableRoles, static function (Role $role) {
            return $role->getIdentifier() === self::$roleIdentifier || array_key_exists(self::$roleIdentifier, $role->getAllParentRoles());
        });
    }

    /**
     * Returns an array with all roles of a user's accounts, including parent roles, the "Everybody" role and the
     * "AuthenticatedUser" role, assuming that the user is logged in.
     *
     * @param Account $account
     * @return Role[] indexed by role identifier
     */
    private function getAllRolesForAccount(Account $account): array
    {
        $roles = [];
        $accountRoles = $account->getRoles();
        foreach ($accountRoles as $currentRole) {
            if (!in_array($currentRole, $roles, true)) {
                $roles[$currentRole->getIdentifier()] = $currentRole;
            }
            foreach ($currentRole->getAllParentRoles() as $currentParentRole) {
                if (!in_array($currentParentRole, $roles, true)) {
                    $roles[$currentParentRole->getIdentifier()] = $currentParentRole;
                }
            }
        }

        return $roles;
    }

    /**
     * Returns whether it is allowed to add/remove the changed roles.
     *
     * - Roles not being "FE user roles" can never be set
     *
     * @param array $roleIdentifiersToSet
     * @return bool
     */
    private function onlyFrontendRoles(array $roleIdentifiersToSet): bool
    {
        $frontendUserRoleIdentifiers = array_keys($this->getFrontendUserRoles());

        return array_diff($roleIdentifiersToSet, $frontendUserRoleIdentifiers) === [];
    }

    /**
     * Add any non-FE roles from the current $account roles to $roleIdentifiersToSet
     *
     * @param array $roleIdentifiersToSet
     * @param Account $account
     * @return array
     */
    protected function addExistingNonFrontendUserRoles(array $roleIdentifiersToSet, Account $account): array
    {
        return array_unique(array_merge(
            $roleIdentifiersToSet,
            array_keys(array_filter(
                $this->getAllRolesForAccount($account),
                static function (Role $role) {
                    return !$role->isAbstract() && !($role->getIdentifier() === self::$roleIdentifier || array_key_exists(self::$roleIdentifier, $role->getAllParentRoles()));
                }
            ))
        ));
    }
}
