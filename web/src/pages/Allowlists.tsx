import { useState } from 'react';
import { ListChecks, Plus, Trash2 } from 'lucide-react';
import { api } from '../api';
import { can, type Role } from '../App';
import { Badge, Button, Card, Empty, ErrorBox, Field, Modal, SkeletonCard, ago, ask, cx, inputCls, toast, useAsync } from '../ui';

interface List { name: string; description: string; created_at: string; updated_at: string; items: { value: string; comment?: string; created_at?: string; expiration?: string }[] }

export default function Allowlists({ role }: { role: Role }) {
  const { data, error, reload } = useAsync(() => api<List[]>('/allowlists'), []);
  const [adding, setAdding] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const op = can(role, 'operator');
  const isAdmin = can(role, 'admin');

  const remove = async (name: string, value: string) => {
    if (!await ask({ title: `Remove ${value}?`, body: <>It is taken out of <b className="text-slate-200">{name}</b> and CrowdSec can ban it again.</>, tone: 'danger', confirmLabel: 'Remove' })) return;
    await api(`/allowlists/${encodeURIComponent(name)}/remove`, { method: 'POST', json: { values: [value] } });
    toast(`Removed ${value}`);
    reload();
  };
  const drop = async (name: string) => {
    if (!await ask({ title: `Delete ${name}?`, body: 'The whole allowlist and every entry in it are removed. This cannot be undone.', tone: 'danger', confirmLabel: 'Delete allowlist' })) return;
    await api(`/allowlists/${encodeURIComponent(name)}`, { method: 'DELETE' });
    toast(`Deleted ${name}`);
    reload();
  };

  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-3xl font-semibold text-white sm:text-[34px]">Allowlists</h1>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">IPs and ranges CrowdSec will never ban.</p>
          <div className="hairline mt-4 w-40" />
        </div>
        {isAdmin && <Button tone="primary" onClick={() => setCreating(true)}><Plus size={16} /> New allowlist</Button>}
      </div>
      <ErrorBox error={error} />
      <div className="stagger grid gap-6 xl:grid-cols-2">
        {!data && !error && [3, 2].map((n, i) => <SkeletonCard key={i} rows={n} />)}
        {(data ?? []).map((l) => (
          <Card key={l.name} title={l.name} icon={<ListChecks size={16} />}
            actions={<div className="flex gap-2">
              {op && <Button onClick={() => setAdding(l.name)}><Plus size={14} /> Add</Button>}
              {isAdmin && <Button tone="ghost" onClick={() => drop(l.name)}><Trash2 size={14} /></Button>}
            </div>}>
            <p className="-mt-2 mb-3 text-sm text-slate-400">{l.description}</p>
            <ul className="divide-y divide-white/5">
              {l.items.map((i) => (
                <li key={i.value} className="flex items-center justify-between gap-3 py-2">
                  <div>
                    <div className="font-mono text-sm text-cyan-200">{i.value}</div>
                    <div className="text-xs text-slate-500">{i.comment || 'no comment'}{i.created_at && ` · added ${ago(i.created_at)}`}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    {i.expiration && !i.expiration.startsWith('0001') && <Badge tone="amber">until {i.expiration.slice(0, 10)}</Badge>}
                    {op && <Button tone="ghost" onClick={() => remove(l.name, i.value)}><Trash2 size={14} /></Button>}
                  </div>
                </li>
              ))}
            </ul>
            {!l.items.length && <Empty>Empty</Empty>}
          </Card>
        ))}
      </div>
      <AddModal name={adding} onClose={() => setAdding(null)} onDone={reload} />
      <CreateModal open={creating} onClose={() => setCreating(false)} onDone={reload} />
    </div>
  );
}

function AddModal({ name, onClose, onDone }: { name: string | null; onClose: () => void; onDone: () => void }) {
  const [text, setText] = useState('');
  const [comment, setComment] = useState('');
  const [error, setError] = useState<string | null>(null);
  const add = async () => {
    try {
      const values = text.split(/[\s,;]+/).filter(Boolean);
      const r = await api<{ count: number }>(`/allowlists/${encodeURIComponent(name!)}/add`, { method: 'POST', json: { values, comment } });
      toast(`Added ${r.count} to ${name}`);
      setText(''); setComment(''); onClose(); onDone();
    } catch (e: any) { setError(e.message); }
  };
  return (
    <Modal open={!!name} onClose={onClose} title={`Add to ${name}`}>
      <div className="space-y-4">
        <Field label="IPs or ranges" hint="One per line."><textarea className={cx(inputCls, 'h-32 font-mono')} value={text} onChange={(e) => setText(e.target.value)} /></Field>
        <Field label="Comment"><input className={inputCls} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="who / why" /></Field>
        <ErrorBox error={error} />
        <div className="flex justify-end"><Button tone="primary" onClick={add}>Add</Button></div>
      </div>
    </Modal>
  );
}

function CreateModal({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [error, setError] = useState<string | null>(null);
  const create = async () => {
    try {
      await api('/allowlists', { method: 'POST', json: { name, description } });
      toast(`Created ${name}`);
      setName(''); setDescription(''); onClose(); onDone();
    } catch (e: any) { setError(e.message); }
  };
  return (
    <Modal open={open} onClose={onClose} title="New allowlist">
      <div className="space-y-4">
        <Field label="Name"><input className={inputCls} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. partners" /></Field>
        <Field label="Description"><input className={inputCls} value={description} onChange={(e) => setDescription(e.target.value)} /></Field>
        <ErrorBox error={error} />
        <div className="flex justify-end"><Button tone="primary" onClick={create}>Create</Button></div>
      </div>
    </Modal>
  );
}
