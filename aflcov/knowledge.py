from collections import defaultdict
from angr.knowledge_plugins import KnowledgeBasePlugin

class Coverage(KnowledgeBasePlugin, dict):

    def __init__(self, kb):
        super(Coverage, self).__init__()
        self._kb = kb

        self.pre_nodes = set()
        self.succ_nodes = set()
        self.target_nodes = set()

    def copy(self):
        o = IndirectJumps(self._kb)

        o.pre_nodes.update(self.pre_nodes)
        o.succ_nodes.update(self.succ_nodes)
        o.target_nodes.update(self.target_nodes)
        

    def register_pre_blocks(self, nodes=[]):
        for addr in nodes:
            self.pre_nodes.add(addr)

    def register_succ_blocks(self, nodes=[]):
        for addr in nodes:
            self.succ_nodes.add(addr)

    def register_target_blocks(self, nodes=[]):
        for addr in nodes:
            self.target_nodes.add(addr)

    def target_pre_or_succ(self, addr):
        if addr in self.pre_nodes:
            return "Pre"
        elif addr in self.succ_nodes:
            return "Succ"
        elif addr in self.target_nodes:
            return "Target"
        else:
            return "-"


KnowledgeBasePlugin.register_default('cov', Coverage)
