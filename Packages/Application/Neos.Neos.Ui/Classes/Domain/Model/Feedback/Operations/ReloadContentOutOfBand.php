<?php
namespace Neos\Neos\Ui\Domain\Model\Feedback\Operations;

/*
 * This file is part of the Neos.Neos.Ui package.
 *
 * (c) Contributors of the Neos Project - www.neos.io
 *
 * This package is Open Source Software. For the full copyright and license
 * information, please view the LICENSE file which was distributed with this
 * source code.
 */

use Neos\ContentRepository\Domain\Model\NodeInterface;
use Neos\Flow\Annotations as Flow;
use Neos\Flow\Mvc\Controller\ControllerContext;
use Neos\Fusion\Core\Cache\ContentCache;
use Neos\Fusion\Exception as FusionException;
use Neos\Neos\Ui\Domain\Model\AbstractFeedback;
use Neos\Neos\Ui\Domain\Model\FeedbackInterface;
use Neos\Neos\Ui\Domain\Model\RenderedNodeDomAddress;
use Neos\Neos\View\FusionView as FusionView;
use Neos\Neos\Fusion\Helper\CachingHelper;

class ReloadContentOutOfBand extends AbstractFeedback
{
    /**
     * @var NodeInterface
     */
    protected $node;

    /**
     * The node dom address
     *
     * @var RenderedNodeDomAddress
     */
    protected $nodeDomAddress;

    /**
     * @Flow\Inject
     * @var ContentCache
     */
    protected $contentCache;

    /**
     * @Flow\Inject
     * @var CachingHelper
     */
    protected $cachingHelper;

    /**
     * Set the node
     *
     * @param NodeInterface $node
     * @return void
     */
    public function setNode(NodeInterface $node)
    {
        $this->node = $node;
    }

    /**
     * Get the node
     *
     * @return NodeInterface
     */
    public function getNode()
    {
        return $this->node;
    }

    /**
     * Set the node dom address
     *
     * @param RenderedNodeDomAddress $nodeDomAddress
     * @return void
     */
    public function setNodeDomAddress(RenderedNodeDomAddress $nodeDomAddress = null)
    {
        $this->nodeDomAddress = $nodeDomAddress;
    }

    /**
     * Get the node dom address
     *
     * @return RenderedNodeDomAddress
     */
    public function getNodeDomAddress()
    {
        return $this->nodeDomAddress;
    }

    /**
     * Get the type identifier
     *
     * @return string
     */
    public function getType()
    {
        return 'Neos.Neos.Ui:ReloadContentOutOfBand';
    }

    /**
     * Get the description
     *
     * @return string
     */
    public function getDescription()
    {
        return sprintf('Rendering of node "%s" required.', $this->getNode()->getPath());
    }

    /**
     * Checks whether this feedback is similar to another
     *
     * @param FeedbackInterface $feedback
     * @return boolean
     */
    public function isSimilarTo(FeedbackInterface $feedback)
    {
        if (!$feedback instanceof ReloadContentOutOfBand) {
            return false;
        }

        return (
            $this->getNode()->getContextPath() === $feedback->getNode()->getContextPath() &&
            $this->getNodeDomAddress() == $feedback->getNodeDomAddress()
        );
    }

    /**
     * Serialize the payload for this feedback
     *
     * @return mixed
     */
    public function serializePayload(ControllerContext $controllerContext)
    {
        return [
            'contextPath' => $this->getNode()->getContextPath(),
            'nodeDomAddress' => $this->getNodeDomAddress(),
            'renderedContent' => $this->renderContent($controllerContext)
        ];
    }

    /**
     * Render the node
     *
     * @param ControllerContext $controllerContext
     * @return string
     */
    protected function renderContent(ControllerContext $controllerContext)
    {
        $cacheTags = $this->cachingHelper->nodeTag($this->getNode());
        foreach ($cacheTags as $tag) {
            $this->contentCache->flushByTag($tag);
        }

        $nodeDomAddress = $this->getNodeDomAddress();

        $fusionView = new FusionView();
        $fusionView->setControllerContext($controllerContext);

        $fusionView->assign('value', $this->getNode());
        $fusionView->setFusionPath($nodeDomAddress->getFusionPathForContentRendering());

        return $fusionView->render();
    }

    public function serialize(ControllerContext $controllerContext)
    {
        try {
            return parent::serialize($controllerContext);
        } catch (FusionException $e) {
            // in case there was a rendering error, we just try to reload the document as fallback. Needed
            // e.g. when adding validators to Neos.FormBuilder
            return (new ReloadDocument())->serialize($controllerContext);
        }
    }
}
