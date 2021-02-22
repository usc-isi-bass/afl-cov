import logging
l = logging.getLogger('angr.analyses.axt.aflcoverage')


import os
from angr.analyses import Analysis, register_analysis
from trimAFL import trim_analysis


class AflCoverage(Analysis):
    def __init__(self, binary, cfg, target, is_addr=False, rewrite=False):
        super(AflCoverage, self).__init__()
        self.cfg = cfg
        if not is_addr:
            if target == "-":
                return 
            t_name = target 
            if self.project.loader.find_symbol(t_name) is None:
                return
            t_addr = self.project.loader.find_symbol(t_name).rebased_addr
            self.target_addr = t_addr
        else:
            self.target_addr = target

        self._analyse()

        if rewrite:
            trim_analysis.insert_interrupt(binary, self.project.kb.cov.trim_addrs)
            exit(0)

    def _analyse(self):
        kb = self.project.kb

        target_addr, pre_blocks, succ_blocks, trim_blocks = trim_analysis.get_target_pred_succ_trim_nodes(self.project, self.cfg, self.target_addr)

        # TODO
        kb.cov.register_target_blocks(target_addr)
        kb.cov.register_pre_blocks(pre_blocks)
        kb.cov.register_succ_blocks(succ_blocks)
        kb.cov.register_trim_blocks(trim_blocks)


register_analysis(AflCoverage, 'AflCoverage')

