import logging
l = logging.getLogger('angr.analyses.axt.aflcoverage')


import os
from angr.analyses import Analysis, register_analysis

def get_target_pred_succ_nodes(proj, cfg, target_name):
    pred_nodes = {}
    t_name = target_name 
    t_addr = proj.loader.find_symbol(t_name).rebased_addr
    t_node = None
    for node in cfg.graph.nodes():
        if node.block.addr == t_addr:
            t_node = node
            break

    # Put all predessors into pred_nodes
    predecessors = t_node.predecessors
    while len(predecessors) != 0:
        new_predecessors = []
        for node in predecessors:
            if node.block.addr in pred_nodes or node == t_node:
                continue
            pred_nodes[node.block.addr] = node
            for pre_node in node.predecessors:
                if pre_node.block is not None and pre_node.block.addr not in pred_nodes:
                    new_predecessors.append(pre_node)
        predecessors = new_predecessors

    succ_nodes = {}
    successors = t_node.successors
    while len(successors) != 0:
        new_successors = []
        for node in successors:
            if node.block.addr in succ_nodes:
                continue
            succ_nodes[node.block.addr] = node
            for succ_node in node.successors:
                if succ_node.block is not None and succ_node.block.addr not in succ_nodes:
                    new_successors.append(succ_node)
        successors = new_successors

    target_nodes = {}
    target_nodes[t_node.addr] = t_node
    return target_nodes, pred_nodes, succ_nodes


class AflCoverage(Analysis):
    def __init__(self, cfg, target_func):
        super(AflCoverage, self).__init__()
        self.cfg = cfg
        self.target_func = target_func
        self._analyse()

    def _analyse(self):
        kb = self.project.kb

        target_addr, pre_blocks, succ_blocks = get_target_pred_succ_nodes(self.project, self.cfg, self.target_func)

        # TODO
        kb.cov.register_target_blocks(target_addr)
        kb.cov.register_pre_blocks(pre_blocks)
        kb.cov.register_succ_blocks(succ_blocks)


register_analysis(AflCoverage, 'AflCoverage')

