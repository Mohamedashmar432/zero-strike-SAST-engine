# ZS-PY-065: shutil.rmtree() with a tainted path (recursive arbitrary deletion)
import shutil
workspace = request.args.get('workspace')
shutil.rmtree(workspace)
