/** Fixed Main-owned pure canonical operations. This helper never starts remote transport. */
export const publicationPython = String.raw`
import sys,json,hashlib,pathlib,shlex
root=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(root))
from bridge_core import native_html_release as n
from bridge_core import report_publish_queue as q
from scripts import publish_generic_html_direct as direct
from scripts import publish_worksheet_html as tx
from bridge_core.html_contract import protected_release_host
request=json.load(sys.stdin);op=request['operation'];b=request.get('binding')
# This must succeed before any canonical queue write. No lossy generation conversion.
if 'generation' in n.INT_KEYS:raise RuntimeError('NATIVE_ROOT_GENERATION_CONTRACT')
if op=='contract':value={'schema':n.SCHEMA,'generation':'string','dispatcher':n.DISPATCHER}
else:
 marker=n.marker_for(b);relative='core/imessage/imessage-'+marker['binding_digest'][:32]+'.html'
 if b['artifactRelative']!=relative:raise RuntimeError('NATIVE_ROUTE_MISMATCH')
 slug=pathlib.PurePosixPath(relative).stem
 if op=='stage':
  from bridge_core.publication_consumer_controller import managed_publication_job
  with managed_publication_job(request['managedExpected']):
   from bridge_core.publish_html import publish_html_report
   text=request['text']
   if not isinstance(text,str) or len(text.encode())>32000 or hashlib.sha256(text.encode()).hexdigest()!=b['completedOutputSha256']:raise RuntimeError('NATIVE_SOURCE_MISMATCH')
   try:publish_html_report('long-form',data={'title':'Partner reply','body_markdown':text},title='Partner reply',slug=slug,overwrite=True,scope='core',category='imessage',source='bluebubbles-connect',provenance=marker,template_family='home-kb')
   except RuntimeError as error:
    if not str(error).startswith('generic HTML publish was not applied:'):raise
   artifact=pathlib.Path(request['artifactRoot'])/relative
   digest=hashlib.sha256(n._read_regular(artifact,n.MAX_ARTIFACT_BYTES)).hexdigest()
   v=direct.select(slug=slug,artifact_sha256=digest,latest=False);value=n.NativeRelease.snapshot(v)
 elif op=='inspect':
  artifact=pathlib.Path(request['artifactRoot'])/relative
  digest=hashlib.sha256(n._read_regular(artifact,n.MAX_ARTIFACT_BYTES)).hexdigest()
  v=direct.select_native_reconcile(slug=slug,artifact_sha256=digest);value=n.NativeRelease.snapshot(v)
 elif op=='commands':
  n.validate_binding(b,fresh=False)
  expected=n.release_pair(b);wire=request['pair'];name=pathlib.PurePosixPath(relative).name
  if type(wire)is not dict or wire!=expected or set(wire)!={name,name[:-5]+'.json'}:raise RuntimeError('NATIVE_PAIR_MISMATCH')
  # Wire is an object; the canonical helpers take an explicitly ordered tuple list.
  pair=[(name,wire[name]),(name[:-5]+'.json',wire[name[:-5]+'.json'])]
  release=n.release_id(b);state=direct.GENERIC_STATE_DIR;remote=direct.REPORTS_REMOTE_ROOT+'/core/imessage';stage=state+'/staging/'+release
  public=direct._policy()[1]+'/reports/'+relative
  bootstrap='set -eu; umask 077; user=$(id -un); group=$(id -gn); '+' '.join('sudo install -d -o "$user" -g "$group" -m 0700 '+shlex.quote(p) for p in [state,state+'/staging',state+'/lkg',state+'/receipts'])
  bootstrap+='; sudo install -d -o "$user" -g "$group" -m 0755 '+shlex.quote(remote)+'; test -d '+shlex.quote(remote)+' -a -w '+shlex.quote(remote)+'; test ! -e '+shlex.quote(stage)+'; mkdir '+shlex.quote(stage)
  receipt=state+'/receipts/'+release+'.json'
  readReceipt='if test -f '+shlex.quote(receipt)+'; then cat '+shlex.quote(receipt)+'; else printf absent; fi'
  checks=['set -eu']
  for filename,_ in pair:
   final=shlex.quote(remote+'/'+filename);checks.append('test -f '+final+'; sha256sum '+final+" | awk '{print $1}'")
  value={'host':protected_release_host(),'bootstrap':bootstrap,'upload':stage+'/', 'transaction':tx._remote_command(release_id=release,pair=pair,public_url=public,remote_dir=remote,state_dir=state,readback_query_key='generic_release'),'receipt':readReceipt,'verify':'; '.join(checks),'publicUrl':public,'orderedPair':pair,'releaseId':release}
 else:raise RuntimeError('NATIVE_FIXED_OPERATION')
print(json.dumps(value,ensure_ascii=False,separators=(',',':')))
`;

/** Fixed generic entry; only Main supplies independently bound expected argv. No arbitrary module. */
export const publicationManagedEntryPython = String.raw`
import json,runpy,sys
root=sys.argv.pop(1);sys.path.insert(0,root)
expected=json.loads(sys.argv.pop(1))
from bridge_core.publication_consumer_controller import managed_publication_job
with managed_publication_job(expected):
 runpy.run_module('scripts.publish_generic_html_direct',run_name='__main__')
`;
