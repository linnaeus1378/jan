<?php
namespace Neos\Neos\Ui\Domain\Model\Changes;

/*
 * This file is part of the Neos.Neos.Ui package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

class CreateAfter extends AbstractCreate
{
    /**
     * Get the insertion mode (before|after|into) that is represented by this change
     *
     * @return string
     */
    public function getMode()
    {
        return 'after';
    }

    /**
     * Check if the new node's node type is allowed in the requested position
     *
     * @return boolean
     */
    public function canApply()
    {
        $parent = $this->getSubject()->getParent();
        $nodeType = $this->getNodeType();

        return $parent->isNodeTypeAllowedAsChildNode($nodeType);
    }

    /**
     * Create a new node after the subject
     *
     * @return void
     */
    public function apply()
    {
        if ($this->canApply()) {
            $subject = $this->getSubject();
            $parent = $subject->getParent();
            $node = $this->createNode($parent);

            $node->moveAfter($subject);
            $this->updateWorkspaceInfo();
        }
    }
}
