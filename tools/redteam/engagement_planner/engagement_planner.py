#!/usr/bin/env python3
"""
Engagement planner: generate a Markdown plan and checklist for an authorized red-team engagement.
This is a planning/documentation tool only — it contains no offensive code.
"""
import argparse
from datetime import datetime


def render_markdown(target, scope, objectives, out_path, author):
    now = datetime.utcnow().isoformat() + 'Z'
    md = [f"# Engagement Plan for {target}\n",
          f"**Author**: {author}\n",
          f"**Generated**: {now}\n",
          "## Scope\n",
          scope + "\n",
          "## Objectives\n",
          '\n'.join([f"- {o}" for o in objectives]) + "\n",
          "## Rules of Engagement\n",
          "- Authorized systems only\n- No persistence or destructive actions without explicit approval\n",
          "## Checklist\n",
          "- [ ] Confirm written authorization\n- [ ] Notify stakeholders\n- [ ] Backup critical systems\n- [ ] Define safe-stop conditions\n",
          "## Notes\n",
          "Add environment-specific notes here.\n"]
    with open(out_path, 'w') as f:
        f.writelines(md)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--target', required=True)
    p.add_argument('--scope', required=True)
    p.add_argument('--objective', action='append', default=[], help='High-level objective (can be specified multiple times)')
    p.add_argument('--out', default='engagement_plan.md')
    p.add_argument('--author', default='unknown')
    args = p.parse_args()

    if not args.objective:
        args.objective = ['Assess external exposure', 'Validate detection and response']

    render_markdown(args.target, args.scope, args.objective, args.out, args.author)
    print('Wrote', args.out)


if __name__ == '__main__':
    main()
