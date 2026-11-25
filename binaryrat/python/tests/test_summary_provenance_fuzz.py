"""Seeded properties for union citations reached through multiple call paths.

Apache-2.0; Copyright 2026 YurilLAB.
"""

import copy
import json
import random
import unittest

from binaryrat import SummaryReportError, decode_summary_report
from binaryrat.summary_layout import explain_summary
from test_summary_layout import access, report


def generated_report(seed):
    """Call the same leaf and its child on two different offsets of the root object."""
    rng = random.Random(seed)
    doc = report()
    root, leaf, child = doc['summaries']
    solution = doc['solution']
    layout = solution['layout']
    doc['components'] = []
    doc['refused_calls'] = []
    doc['edges'] = []
    solution['states'] = solution['states'][:1]
    solution['derived'] = []
    layout['fields'] = []
    layout['union_candidates'] = []
    root['accesses'] = []

    widths = {'integer': (1, 2, 4, 8), 'floating_point': (4, 8)}
    views = []
    for owner, kind, local_offset in ((leaf, 'integer', -8), (child, 'floating_point', 4)):
        owner['accesses'] = []
        start = int(owner['function_address'], 16)
        for width in rng.sample(widths[kind], rng.randint(1, len(widths[kind]))):
            ids = []
            for _ in range(rng.randint(1, 2)):
                site = start + 4 * (1 + len(owner['accesses']))
                row = access(owner['id'], local_offset, site, width, kind)
                row['typed_use'] = dict(address_space='ram', address=f'{site + 0x80:x}',
                                        pcode_order=7, operation='INT_XOR' if kind == 'integer' else 'FLOAT_ADD')
                owner['accesses'].append(row)
                ids.append(row['evidence_id'])
            views.append(dict(kind=kind, width=width, evidence_ids=ids))
    rng.shuffle(views)

    def add_edge(caller, callee, displacement, site):
        doc['edges'].append(dict(caller=caller['id'], callee=callee['id'], offset=displacement,
                                 address_space='ram', address=f'{site:x}', pcode_order=1,
                                 evidence_id=f"{caller['id']}/call/ram/{site:x}/1/arg/0",
                                 argument_index=0, callee_address_space='ram',
                                 callee_address=callee['function_address']))
        return len(doc['edges']) - 1

    def reach(owner, parent, edge_index):
        previous = solution['states'][parent]
        displacement = previous['offset'] + doc['edges'][edge_index]['offset']
        state = len(solution['states'])
        solution['states'].append(dict(summary=owner['id'], offset=displacement,
                                       hops=previous['hops'] + 1, edge=edge_index, parent=parent))
        for index, row in enumerate(owner['accesses']):
            solution['derived'].append(dict(state=state, access=index, offset=displacement + row['offset'],
                                            width=row['width'], storage_view=row['storage_view'],
                                            evidence_id=row['evidence_id']))
        return state

    next_call = add_edge(leaf, child, -12, 0x20c0)
    first_offset = rng.randrange(33)
    offsets = [first_offset, first_offset + rng.randrange(9, 65)]
    calls = [0x1040, 0x1048]
    by_width = {}
    for view in views:
        by_width.setdefault(view['width'], []).extend(view['evidence_ids'])
    for offset, site in zip(offsets, calls):
        leaf_state = reach(leaf, 0, add_edge(root, leaf, offset + 8, site))
        reach(child, leaf_state, next_call)
        for width, ids in sorted(by_width.items()):
            layout['fields'].append(dict(offset=offset, width=width, evidence_ids=sorted(ids),
                                         overlaps_other_fields=len(by_width) > 1,
                                         evidence_strength=len(ids) / (len(ids) + 1)))
        count = sum(len(ids) for ids in by_width.values())
        layout['union_candidates'].append(dict(offset=offset, views=copy.deepcopy(views),
                                               evidence_strength=count / (count + 1)))
    layout['minimum_extent'] = max(offsets) + max(by_width)
    layout['has_overlaps'] = len(by_width) > 1
    rng.shuffle(solution['derived'])
    return doc, offsets, calls


class SummaryProvenanceProperties(unittest.TestCase):
    def test_shared_loads_resolve_at_each_offset_with_the_selected_path(self):
        for seed in range(24):
            doc, offsets, calls = generated_report(seed)
            with self.subTest(seed=seed):
                parsed = decode_summary_report(json.dumps(doc))
                for index, candidate in enumerate(parsed.union_candidates):
                    self.assertEqual(candidate.offset, offsets[index])
                    lines = '\n'.join(explain_summary(parsed, offset=candidate.offset))
                    self.assertIn(f'ram:{calls[index]:x}', lines)
                    self.assertNotIn(f'ram:{calls[1 - index]:x}', lines)
                    self.assertIn('ram:20c0', lines)
                    for owner in doc['summaries'][1:]:
                        for row in owner['accesses']:
                            witness = row['typed_use']
                            evidence, = [line for line in lines.splitlines()
                                         if f"LOAD at ram:{row['address']} " in line]
                            for fact in (row['storage_view'], witness['operation'], 'ram:' + witness['address'],
                                         f"p-code {witness['pcode_order']}", f'ram:{calls[index]:x}'):
                                self.assertIn(fact, evidence)
                            self.assertEqual('ram:20c0' in evidence, owner is doc['summaries'][2])
                    for view in candidate.views:
                        ids = {row.evidence_id for row, path in parsed.evidence_for(candidate.offset, view.width)
                               if row.storage_view == view.kind and path[0].site.offset == calls[index]}
                        self.assertEqual(set(view.evidence_ids), ids)

    def test_mutating_one_citation_or_group_refuses_the_report(self):
        for seed in range(24):
            doc, _, _ = generated_report(seed)
            for fault in ('missing', 'wrong kind', 'duplicate citation', 'object', 'empty', 'wrong width',
                          'wrong offset', 'missing kind', 'duplicate view', 'duplicate candidate', 'store',
                          'unrelated consumer', 'field omission'):
                with self.subTest(seed=seed, fault=fault):
                    damaged = copy.deepcopy(doc)
                    layout = damaged['solution']['layout']
                    candidate = layout['union_candidates'][0]
                    views = candidate['views']
                    view = views[seed % len(views)]
                    ids = view['evidence_ids']
                    if fault == 'missing':
                        ids[0] += '/missing'
                    elif fault == 'wrong kind':
                        ids[0] = next(v['evidence_ids'][0] for v in views if v['kind'] != view['kind'])
                    elif fault == 'duplicate citation':
                        ids.append(ids[0])
                    elif fault == 'object':
                        ids[0] = {'id': ids[0]}
                    elif fault == 'empty':
                        ids.clear()
                    elif fault == 'wrong width':
                        view['width'] = 3
                    elif fault == 'wrong offset':
                        candidate['offset'] += 1
                    elif fault == 'missing kind':
                        candidate['views'] = [v for v in views if v['kind'] == view['kind']]
                    elif fault == 'duplicate view':
                        views.append(copy.deepcopy(view))
                    elif fault == 'duplicate candidate':
                        layout['union_candidates'].append(copy.deepcopy(candidate))
                    elif fault in ('store', 'unrelated consumer'):
                        source = next(row for summary in damaged['summaries'] for row in summary['accesses']
                                      if row['evidence_id'] == ids[0])
                        if fault == 'store':
                            source['operation'] = 'STORE'
                        else:
                            source['typed_use']['operation'] = 'COPY'
                    else:
                        field = next(f for f in layout['fields'] if f['offset'] == candidate['offset']
                                     and f['width'] == view['width'])
                        field['evidence_ids'].remove(ids[0])
                    with self.assertRaises(SummaryReportError):
                        decode_summary_report(json.dumps(damaged))


if __name__ == '__main__':
    unittest.main()
