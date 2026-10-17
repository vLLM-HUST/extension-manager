"""Behavioral candidate tests. Source only; deliberately not run in live window."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from experiments.formal_campaign import h3_observer_dispatch as dispatch


class OriginalObserverNineTests(unittest.TestCase):
    def packet(self,root):
        protocol=json.loads((Path(dispatch.__file__).parent/'protocol.json').read_bytes())
        starts=[]
        for repetition,arms in enumerate(protocol['schedule'],1):
            for order,arm in enumerate(arms,1):
                sid=f'observer-loss-r{repetition}-{arm}'
                recipe=root/(sid+'.json')
                recipe.write_text(json.dumps({'arms':{arm:{'phases':[{
                    'native_bootstrap':{'output':str(root/'actual'/sid/'native0')}}]}}}))
                starts.append({'start_id':sid,'repetition':repetition,'arm':arm,
                               'arm_order':order,'recipe_template':{'path':str(recipe)}})
        return {'starts':starts},{'cell_id':'observer-loss'},{}

    def run_packet(self,root,packet,result):
        with patch.object(dispatch.registration,'validate_receipt',return_value=packet), \
             patch.object(dispatch.registration,'checked_reference',side_effect=lambda ref:Path(ref['path'])), \
             patch('experiments.formal_campaign.h3_observer_runner.execute',side_effect=result) as execute:
            rows=dispatch.run_nine(root/'campaign.json',root/'receipt.json',root/'actual')
            return rows,execute.call_args_list

    def test_qualified_failed_objectives_are_nine_distinct_rows_without_retry(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);packet=self.packet(root)
            failed={'formal_start_validated':True,'objective_met':False,
                    'cleanup':{'processes_reclaimed':True,'ports_reclaimed':True,
                               'devices_reclaimed':True,'external_services_preserved':True}}
            rows,calls=self.run_packet(root,packet,lambda *a,**k:dict(failed))
            self.assertEqual(len(rows),9)
            self.assertEqual([c.args[2] for c in calls],[s['start_id'] for s in packet[0]['starts']])
            self.assertTrue(all(row['result']['objective_met'] is False for row in rows))

    def test_cleanup_failure_stops_next_launch_and_retains_failed_slot(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);packet=self.packet(root)
            rows,calls=self.run_packet(root,packet,lambda *a,**k:{
                'formal_start_validated':True,'objective_met':False,
                'cleanup':{'devices_reclaimed':False}})
            self.assertEqual(len(rows),1)
            self.assertEqual(len(calls),1)
            terminal=json.loads((root/'actual/terminal.json').read_bytes())
            self.assertEqual(terminal['retry_count'],0)
            self.assertEqual(terminal['original_slots'],9)

    def test_worker_cell_is_rejected_before_any_product_launch(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td);packet=self.packet(root);packet[1]['cell_id']='worker-crash'
            with patch.object(dispatch.registration,'validate_receipt',return_value=packet), \
                 patch('experiments.formal_campaign.h3_observer_runner.execute') as execute:
                with self.assertRaises(Exception):
                    dispatch.run_nine(root/'campaign.json',root/'receipt.json',root/'actual')
                execute.assert_not_called()
