<?php

namespace Hslavich\OneloginSamlBundle\Security\Firewall;

use Hslavich\OneloginSamlBundle\Security\Authentication\Token\SamlToken;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener;

class SamlListener extends AbstractAuthenticationListener
{
    protected $oneLoginAuth;

    /**
     * @param mixed $oneLoginAuth
     */
    public function setOneLoginAuth($oneLoginAuth)
    {
        $this->oneLoginAuth = $oneLoginAuth;
    }

    protected function requiresAuthentication(Request $request)
    {
        return '/saml/acs' === $request->getPathInfo();
    }

    /**
     * Performs authentication.
     *
     * @param Request $request A Request instance
     *
     * @return TokenInterface|Response|null The authenticated token, null if full authentication is not possible, or a Response
     *
     * @throws AuthenticationException if the authentication fails
     */
    protected function attemptAuthentication(Request $request)
    {
        $auth = $this->oneLoginAuth;
        $auth->processResponse();
        if (!$auth->isAuthenticated()) {
            //error
        }

        $attributes = $this->oneLoginAuth->getAttributes();
        $token = new SamlToken();
        $token->setAttributes($attributes);
        $token->setUser($attributes['uid'][0]);

        return  $this->authenticationManager->authenticate($token);
    }
}