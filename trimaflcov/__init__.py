import logging
logging.getLogger('angr.analyses').setLevel(logging.INFO)

from cfgexplorer import CFGExplorerCLI

from . import knowledge
from . import analysis

from cfgexplorer import CFGVisEndpoint
from bingraphvis import ColorNodes
from .vis import AflCovInfo

class AflCFGVisEndpoint(CFGVisEndpoint):
    def __init__(self, cfg):
        super(AflCFGVisEndpoint, self).__init__('cfg', cfg)
    
    def annotate_vis(self, vis, addr):
        kb = self.cfg.project.kb
        vis.add_node_annotator(ColorNodes(filter=lambda node: node.obj.addr in kb.cov.pre_addrs, fillcolor='lightblue'))
        vis.add_node_annotator(ColorNodes(filter=lambda node: node.obj.addr in kb.cov.succ_addrs, fillcolor='orchid'))
        vis.add_node_annotator(ColorNodes(filter=lambda node: node.obj.addr in kb.cov.target_addrs, fillcolor='salmon'))
        vis.add_node_annotator(ColorNodes(filter=lambda node: node.obj.addr in kb.cov.trim_addrs, fillcolor='lightgreen'))
        vis.add_content(AflCovInfo(self.cfg.project))

class AflCovCFGExplorerCLI(CFGExplorerCLI):
    def __init__(self):
        super(AflCovCFGExplorerCLI, self).__init__()    
    

    def _extend_parser(self):
        self.parser.add_argument('target', metavar='target', type=str, help='target <function name/angr rebased addr>')
        self.parser.add_argument('-r', help='rewrite', action='store_true', dest="rewrite", default=False)

    def _postprocess_cfg(self):
        target = self.args.target
        rewrite = self.args.rewrite
        if target.startswith("0x"):
            target_addr = int(target.split("0x", 1)[1], 16)
            self.project.analyses.AflCoverage(self.args.binary, self.cfg, target_addr, True, rewrite)
        else:
            self.project.analyses.AflCoverage(self.args.binary, self.cfg, target, False, rewrite)

    def add_endpoints(self):
        self.app.add_vis_endpoint(AflCFGVisEndpoint(self.cfg))
