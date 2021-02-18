from bingraphvis.base import Content

class AflCovInfo(Content):
    def __init__(self, project):
        super(AflCovInfo, self).__init__('aflcovinfo', ['text'])
        self.project = project
        
    def gen_render(self, n):
        node = n.obj
        n.content[self.name] = {
            'data': [{
                'text': {
                    'content': "Type: %s" % (self.project.kb.cov.target_pre_or_succ(node.addr)),
                    'style':'B',
                    'align':'LEFT'
                }
            }], 
            'columns': self.get_columns()
        }
