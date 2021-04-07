from collections import defaultdict
from angr.knowledge_plugins import KnowledgeBasePlugin

class Coverage(KnowledgeBasePlugin, dict):

    def __init__(self, kb):
        super(Coverage, self).__init__()
        self._kb = kb

        self.pre_addrs = set()
        self.succ_addrs = set()
        self.both_addrs = set()
        self.target_addrs = set()
        self.trim_addrs = set()

    def copy(self):
        o = IndirectJumps(self._kb)

        o.pre_addrs.update(self.pre_addrs)
        o.succ_addrs.update(self.succ_addrs)
        o.both_addrs.update(self.both_addrs)
        o.target_addrs.update(self.target_addrs)
        o.trim_addrs.update(self.trim_addrs)
        

    def register_pre_blocks(self, addrs={}):
        for addr in addrs:
            self.pre_addrs.add(addr)

    def register_succ_blocks(self, addrs={}):
        for addr in addrs:
            self.succ_addrs.add(addr)

    def register_both_blocks(self, addrs={}):
        for addr in addrs:
            self.both_addrs.add(addr)

    def register_target_blocks(self, addrs={}):
        for addr in addrs:
            self.target_addrs.add(addr)

    def register_trim_blocks(self, addrs={}):
        for addr in addrs:
            self.trim_addrs.add(addr)

    def target_pre_or_succ(self, addr):
        if addr in self.pre_addrs:
            return "Pre"
        elif addr in self.succ_addrs:
            return "Succ"
        elif addr in self.target_addrs:
            return "Target"
        else:
            return "-"


KnowledgeBasePlugin.register_default('cov', Coverage)
