import logging
l = logging.getLogger('angr.analyses.axt.aflcoverage')


import os
from angr.analyses import Analysis, register_analysis
from trimAFL import trim_analysis


class AflCoverage(Analysis):
    def __init__(self, binary, cfg, target, is_addr=False, rewrite=False):
        super(AflCoverage, self).__init__()
        self.cfg = cfg
        self.cg = cfg.functions.callgraph
        if not is_addr:
            if target == "-":
                return 
            t_name = target 
            t_symbols = trim_analysis.find_func_symbols(self.project, t_name)
            if len(t_symbols) == 0:
                return
            self.target_addr = t_symbols[0].rebased_addr
        else:
            self.target_addr = target

        self._analyse()

        if rewrite:
            trim_analysis.insert_interrupt(binary, self.project.kb.cov.trim_addrs)
            exit(0)

    def _analyse(self):
        kb = self.project.kb

        target_blocks, pre_blocks, succ_blocks, trim_blocks = trim_analysis.get_target_pred_succ_trim_nodes(self.project, self.cfg, self.cg, [self.target_addr])

        # TODO
        kb.cov.register_target_blocks(target_blocks)
        kb.cov.register_pre_blocks(pre_blocks)
        kb.cov.register_succ_blocks(succ_blocks)
        kb.cov.register_trim_blocks(trim_blocks)


register_analysis(AflCoverage, 'AflCoverage')

