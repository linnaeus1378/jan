<?php
declare(strict_types=1);

namespace Flowpack\Neos\FrontendLogin\Security;

/*
 * This file is part of the Flowpack.Neos.FrontendLogin package.
 *
 * (c) Contributors of the Flowpack Team - flowpack.org
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\Flow\Mvc\ActionRequest;
use Neos\Flow\Mvc\RequestInterface;
use Neos\Flow\Security\RequestPatternInterface;

/**
 * A request pattern that can detect and match "frontend" and "backend" mode
 */
class NeosRequestPattern implements RequestPatternInterface
{

    /**
     * @var array
     */
    protected $options;

    /**
     * Expects options in the form array('matchFrontend' => TRUE/FALSE)
     *
     * @param array $options
     */
    public function __construct(array $options)
    {
        $this->options = $options;
    }

    /**
     * Matches a \Neos\Flow\Mvc\RequestInterface against its set pattern rules
     *
     * @param ActionRequest $request The request that should be matched
     * @return boolean TRUE if the pattern matched, FALSE otherwise
     */
    public function matchRequest(ActionRequest $request)
    {
        if (!$request instanceof ActionRequest) {
            return false;
        }
        $shouldMatchFrontend = isset($this->options['matchFrontend']) && $this->options['matchFrontend'] === true;
        $requestPath = $request->getHttpRequest()->getUri()->getPath();
        $requestPathMatchesBackend = strpos($requestPath, '/neos') === 0 || strpos($requestPath, '@') !== false;
        return $shouldMatchFrontend !== $requestPathMatchesBackend;
    }

}
