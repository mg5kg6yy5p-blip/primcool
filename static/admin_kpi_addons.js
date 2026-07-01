  // ── shared modal plumbing ───────────────────────────────────────────────
  function kpiAddonOpen(title, html){
    document.getElementById('kpiAddonTitle').textContent = title;
    document.getElementById('kpiAddonBody').innerHTML = html;
    document.getElementById('kpiAddonModal').style.display = 'flex';
  }
  function kpiAddonClose(){ document.getElementById('kpiAddonModal').style.display = 'none'; }
  async function kpiAddonApi(method, url, body){
    const opts = { method, headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin' };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(url, opts);
    if (!r.ok) { let m=''; try{ m=(await r.json()).detail || ''; }catch(_){} throw new Error(m || ('HTTP '+r.status)); }
    return r.json();
  }
  function _h(s){ return (s||'').replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c])); }

  // ── Coaching Log panel (Scorecards subtab) ──────────────────────────────
  window.kpiOpenCoachingLog = async function(techId){
    try {
      const r = await kpiAddonApi('GET', `/api/admin/kpi/notes?tech_id=${techId}&note_kind=coaching&limit=50`);
      const items = (r.notes || []).map(n => {
        const archived = (n.status || '') === 'archived';
        const archiveBtn = archived
          ? '<span style="font-size:11px;color:var(--muted-2);">archived</span>'
          : `<button class="btn btn-ghost btn-sm" onclick="kpiArchiveNote(${n.id}, ${techId})" title="Archive this note">Archive</button>`;
        return `
        <div style="border-left:3px solid var(--steel);padding:8px 12px;margin-bottom:8px;background:var(--surface-2);${archived ? 'opacity:.6;' : ''}">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
            <div style="font-size:11px;color:var(--muted);">${_h(n.created_at||'')} · ${_h(n.status||'')}</div>
            ${archiveBtn}
          </div>
          <div style="white-space:pre-wrap;margin-top:4px;">${_h(n.body||'')}</div>
        </div>`;
      }).join('') || '<div style="color:var(--muted-2);">No coaching notes yet.</div>';
      kpiAddonOpen('Coaching Log',
        items +
        `<hr/><textarea id="kpi_coach_body" rows="4" maxlength="2000" placeholder="Add a coaching note..." style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;"></textarea>
         <div style="margin-top:8px;text-align:right;">
           <button class="btn btn-primary" onclick="kpiSaveCoaching(${techId})">Save Coaching Note</button>
         </div>`);
    } catch(e) { alert('Failed to load: ' + e.message); }
  };
  window.kpiSaveCoaching = async function(techId){
    const body = document.getElementById('kpi_coach_body').value.trim();
    if (!body) return alert('Empty');
    try {
      await kpiAddonApi('POST', '/api/admin/kpi/notes', { note_kind:'coaching', tech_id:techId, body });
      kpiAddonClose(); kpiOpenCoachingLog(techId);
    } catch(e){ alert(e.message); }
  };
  window.kpiArchiveNote = async function(noteId, techId){
    if (!confirm('Archive this note? It will be hidden from the active log.')) return;
    try {
      await kpiAddonApi('POST', `/api/admin/kpi/notes/${noteId}/archive`, {});
      kpiAddonClose(); kpiOpenCoachingLog(techId);
    } catch(e){ alert('Failed: ' + e.message); }
  };

  // ── Recognition (any role with note_view) ───────────────────────────────
  window.kpiOpenRecognitionAdd = function(techId){
    kpiAddonOpen('Add Recognition',
      `<textarea id="kpi_recog_body" rows="4" maxlength="2000" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;" placeholder="What did this tech do well?"></textarea>
       <div style="margin-top:8px;text-align:right;">
         <button class="btn btn-primary" onclick="kpiSaveRecognition(${techId})">Save</button>
       </div>`);
  };
  window.kpiSaveRecognition = async function(techId){
    const body = document.getElementById('kpi_recog_body').value.trim();
    if (!body) return;
    try {
      await kpiAddonApi('POST', '/api/admin/kpi/notes', { note_kind:'recognition', tech_id:techId, body });
      kpiAddonClose();
    } catch(e){ alert(e.message); }
  };

  // ── Team-period note (super_admin) ──────────────────────────────────────
  window.kpiOpenTeamPeriodNote = async function(periodKey){
    try {
      const r = await kpiAddonApi('GET', `/api/admin/kpi/notes?note_kind=team_period&period_key=${encodeURIComponent(periodKey)}&limit=10`);
      const existing = (r.notes || [])[0];
      kpiAddonOpen('Team Period Note · ' + periodKey,
        (existing ? `<div style="background:var(--surface-2);padding:10px;border-radius:6px;margin-bottom:10px;white-space:pre-wrap;">${_h(existing.body)}</div>` : '') +
        `<textarea id="kpi_tp_body" rows="5" maxlength="2000" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;" placeholder="Team-wide note for ${periodKey}">${existing? _h(existing.body):''}</textarea>
         <div style="margin-top:8px;text-align:right;">
           <button class="btn btn-primary" onclick="kpiSaveTeamPeriodNote('${periodKey}', ${existing? existing.id : 'null'})">Save</button>
         </div>`);
    } catch(e){ alert(e.message); }
  };
  window.kpiSaveTeamPeriodNote = async function(pk, existingId){
    const body = document.getElementById('kpi_tp_body').value.trim();
    if (!body) return;
    try {
      if (existingId && existingId !== 'null') {
        await kpiAddonApi('PATCH', `/api/admin/kpi/notes/${existingId}`, { body });
      } else {
        await kpiAddonApi('POST', '/api/admin/kpi/notes', { note_kind:'team_period', period_key:pk, body });
      }
      kpiAddonClose();
    } catch(e){ alert(e.message); }
  };

  // ── Score annotation (from Flag Queue cards) ────────────────────────────
  window.kpiOpenScoreAnnotation = async function(scoreId, techId){
    try {
      const r = await kpiAddonApi('GET', `/api/admin/kpi/notes?score_id=${scoreId}&limit=20`);
      const items = (r.notes || []).map(n => `
        <div style="border-left:3px solid var(--teal);padding:6px 10px;margin-bottom:6px;background:var(--teal-bg);">
          <div style="font-size:11px;color:var(--teal-deep);">${_h(n.created_at||'')} · ${_h(n.status||'')}</div>
          <div style="white-space:pre-wrap;margin-top:3px;">${_h(n.body||'')}</div>
        </div>`).join('') || '<div style="color:var(--muted-2);">No annotations yet.</div>';
      kpiAddonOpen('Score Annotation',
        items +
        `<hr/><textarea id="kpi_ann_body" rows="3" maxlength="2000" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;"></textarea>
         <div style="margin-top:8px;text-align:right;">
           <button class="btn btn-primary" onclick="kpiSaveScoreAnnotation(${scoreId}, ${techId||'null'})">Save</button>
         </div>`);
    } catch(e){ alert(e.message); }
  };
  window.kpiSaveScoreAnnotation = async function(scoreId, techId){
    const body = document.getElementById('kpi_ann_body').value.trim();
    if (!body) return;
    try {
      await kpiAddonApi('POST', '/api/admin/kpi/notes', { note_kind:'score_annotation', score_id:scoreId, tech_id:techId||null, body });
      kpiAddonClose(); kpiOpenScoreAnnotation(scoreId, techId);
    } catch(e){ alert(e.message); }
  };

  // ── Goals & PIPs subtab launcher ────────────────────────────────────────
  window.kpiOpenGoalsPanel = async function(techId){
    try {
      const q = techId ? `tech_id=${techId}` : '';
      const r = await kpiAddonApi('GET', '/api/admin/kpi/goals?' + q);
      const rows = (r.goals || []).map(g => `
        <tr style="border-bottom:1px solid var(--border);">
          <td style="padding:6px;">${_h(g.tech_name||g.tech_id)}</td>
          <td style="padding:6px;">${_h(g.goal_kind)}</td>
          <td style="padding:6px;">${_h(g.title||'')}</td>
          <td style="padding:6px;">${_h(g.status)}</td>
          <td style="padding:6px;">${_h(g.target_date||'')}</td>
          <td style="padding:6px;"><button class="btn btn-ghost" onclick="kpiOpenGoalDetail(${g.id})">Open</button></td>
        </tr>`).join('') || '<tr><td colspan="6" style="padding:12px;color:var(--muted-2);">No goals yet.</td></tr>';
      kpiAddonOpen('Goals & PIPs',
        `<div style="margin-bottom:10px;">
           <button class="btn btn-primary" onclick="kpiOpenGoalCreate('development_goal', ${techId||'null'})">+ Development Goal</button>
           <button class="btn btn-danger" onclick="kpiOpenGoalCreate('pip', ${techId||'null'})">+ Initiate PIP</button>
         </div>
         <table style="width:100%;border-collapse:collapse;font-size:13px;">
           <thead><tr style="background:var(--surface-2);"><th style="padding:6px;text-align:left;">Tech</th><th style="padding:6px;text-align:left;">Kind</th><th style="padding:6px;text-align:left;">Title</th><th style="padding:6px;text-align:left;">Status</th><th style="padding:6px;text-align:left;">Target</th><th></th></tr></thead>
           <tbody>${rows}</tbody>
         </table>`);
    } catch(e){ alert(e.message); }
  };
  window.kpiOpenGoalCreate = function(kind, techId){
    const isPip = (kind === 'pip');
    const today = new Date().toISOString().slice(0,10);
    const target = new Date(Date.now() + 90*86400000).toISOString().slice(0,10);
    kpiAddonOpen(isPip ? 'Initiate PIP' : 'Create Development Goal',
      `<input id="g_tech_id" type="number" placeholder="Tech ID" value="${techId&&techId!=='null'?techId:''}" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;"/>
       <input id="g_title" placeholder="Title" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;"/>
       <textarea id="g_desc" rows="3" placeholder="Description" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;"></textarea>
       <div style="display:flex;gap:6px;margin-bottom:6px;">
         <input id="g_start" type="date" value="${today}" style="flex:1;padding:8px;border:1px solid var(--border);border-radius:6px;"/>
         <input id="g_target" type="date" value="${target}" style="flex:1;padding:8px;border:1px solid var(--border);border-radius:6px;"/>
       </div>
       ${isPip ? `<select id="g_sev" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;">
         <option value="standard">Standard</option><option value="final_warning">Final Warning</option></select>` : ''}
       <input id="g_actions" placeholder="Action items (semi-colon separated)" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;"/>
       <div style="text-align:right;"><button class="btn btn-primary" onclick="kpiSaveGoal('${kind}')">Save</button></div>`);
  };
  window.kpiSaveGoal = async function(kind){
    const techId = parseInt(document.getElementById('g_tech_id').value, 10);
    const title = document.getElementById('g_title').value.trim();
    const description = document.getElementById('g_desc').value.trim();
    const start_date = document.getElementById('g_start').value;
    const target_date = document.getElementById('g_target').value;
    const actStr = document.getElementById('g_actions').value.trim();
    const action_items = actStr ? actStr.split(';').map(s=>s.trim()).filter(Boolean) : null;
    const body = { goal_kind:kind, tech_id:techId, title, description,
                   start_date, target_date, action_items };
    if (kind === 'pip') body.pip_severity = document.getElementById('g_sev').value;
    try {
      await kpiAddonApi('POST', '/api/admin/kpi/goals', body);
      kpiAddonClose();
      alert(kind === 'pip' ? 'PIP created in DRAFT — HR must acknowledge before activation.' : 'Goal created.');
    } catch(e){ alert(e.message); }
  };
  window.kpiOpenGoalDetail = async function(goalId){
    try {
      const r = await kpiAddonApi('GET', `/api/admin/kpi/goals/${goalId}`);
      const g = r.goal;
      const ci = (g.checkins || []).map(c => `
        <div style="border-left:3px solid var(--teal);padding:6px 10px;margin-bottom:6px;background:var(--teal-bg);">
          <div style="font-size:11px;color:var(--teal-deep);">${_h(c.checkin_date)} · ${_h(c.status)}</div>
          <div style="white-space:pre-wrap;margin-top:3px;">${_h(c.notes||'')}</div>
        </div>`).join('') || '<div style="color:var(--muted-2);">No check-ins yet.</div>';
      const isPip = (g.goal_kind === 'pip');
      const needsHr = isPip && g.status === 'draft' && !g.hr_acknowledged_at;
      const canActivate = isPip && g.status === 'draft' && g.hr_acknowledged_at;
      kpiAddonOpen(`${g.goal_kind === 'pip' ? 'PIP' : 'Goal'}: ${_h(g.title)}`,
        `<div><strong>Tech:</strong> ${_h(g.tech_name||g.tech_id)} · <strong>Status:</strong> ${_h(g.status)}</div>
         <div><strong>Start:</strong> ${_h(g.start_date)} → <strong>Target:</strong> ${_h(g.target_date)}</div>
         <p style="white-space:pre-wrap;">${_h(g.description||'')}</p>
         ${needsHr ? '<div style="background:var(--teal-bg);padding:8px;border-radius:6px;color:var(--teal-deep);">Awaiting HR acknowledgement.</div>' : ''}
         ${canActivate ? `<button class="btn btn-primary" onclick="kpiActivatePip(${g.id})">Activate PIP</button>` : ''}
         <h4>Check-ins</h4>${ci}
         <hr/>
         <div style="display:flex;gap:6px;margin-bottom:6px;">
           <input id="ci_date" type="date" value="${new Date().toISOString().slice(0,10)}" style="flex:1;padding:6px;border:1px solid var(--border);border-radius:6px;"/>
           <select id="ci_status" style="flex:1;padding:6px;border:1px solid var(--border);border-radius:6px;">
             <option value="on_track">on_track</option><option value="at_risk">at_risk</option>
             <option value="off_track">off_track</option><option value="met">met</option>
           </select>
         </div>
         <textarea id="ci_notes" rows="2" placeholder="Check-in notes" style="width:100%;padding:6px;border:1px solid var(--border);border-radius:6px;"></textarea>
         <div style="text-align:right;margin-top:6px;"><button class="btn btn-primary" onclick="kpiAddCheckin(${g.id})">Add Check-in</button></div>
         <hr/>
         <details><summary>Close goal</summary>
           <select id="close_outcome" style="padding:6px;border:1px solid var(--border);border-radius:6px;margin:6px 0;">
             <option value="met">met</option><option value="not_met">not_met</option><option value="withdrawn">withdrawn</option></select>
           <textarea id="close_summary" rows="2" placeholder="Outcome summary" style="width:100%;padding:6px;border:1px solid var(--border);border-radius:6px;"></textarea>
           <button class="btn btn-danger" onclick="kpiCloseGoal(${g.id})">Close</button>
         </details>`);
    } catch(e){ alert(e.message); }
  };
  window.kpiActivatePip = async function(id){
    if (!confirm('Activate this PIP?')) return;
    try { await kpiAddonApi('POST', `/api/admin/kpi/goals/${id}/activate`); kpiOpenGoalDetail(id); }
    catch(e){ alert(e.message); }
  };
  window.kpiAddCheckin = async function(id){
    const checkin_date = document.getElementById('ci_date').value;
    const status = document.getElementById('ci_status').value;
    const notes = document.getElementById('ci_notes').value.trim();
    if (!notes) return alert('Notes required');
    try { await kpiAddonApi('POST', `/api/admin/kpi/goals/${id}/checkins`, { checkin_date, status, notes }); kpiOpenGoalDetail(id); }
    catch(e){ alert(e.message); }
  };
  window.kpiCloseGoal = async function(id){
    const outcome_status = document.getElementById('close_outcome').value;
    const outcome_summary = document.getElementById('close_summary').value.trim();
    if (!outcome_summary) return alert('Outcome summary required');
    try { await kpiAddonApi('POST', `/api/admin/kpi/goals/${id}/close`, { outcome_status, outcome_summary }); kpiAddonClose(); }
    catch(e){ alert(e.message); }
  };

  // ── HR Acknowledgement Queue (hr_admin) ─────────────────────────────────
  window.kpiOpenHrPipQueue = async function(){
    try {
      const r = await kpiAddonApi('GET', '/api/admin/kpi/pips/active');
      const drafts = (r.pips || []).filter(p => p.status === 'draft' && !p.hr_acknowledged_at);
      const rows = drafts.map(p => `
        <tr style="border-bottom:1px solid var(--border);">
          <td style="padding:6px;">${_h(p.tech_name||p.tech_id)}</td>
          <td style="padding:6px;">${_h(p.title||'')}</td>
          <td style="padding:6px;">${_h(p.opened_at||'')}</td>
          <td style="padding:6px;"><button class="btn btn-primary" onclick="kpiHrAck(${p.id})">Acknowledge</button></td>
        </tr>`).join('') || '<tr><td colspan="4" style="padding:12px;color:var(--muted-2);">No draft PIPs awaiting acknowledgement.</td></tr>';
      kpiAddonOpen('HR Acknowledgement Queue',
        `<table style="width:100%;border-collapse:collapse;font-size:13px;">
           <thead><tr style="background:var(--surface-2);"><th style="padding:6px;text-align:left;">Tech</th><th style="padding:6px;text-align:left;">Title</th><th style="padding:6px;text-align:left;">Opened</th><th></th></tr></thead>
           <tbody>${rows}</tbody></table>`);
    } catch(e){ alert(e.message); }
  };
  window.kpiHrAck = async function(id){
    try { await kpiAddonApi('POST', `/api/admin/kpi/goals/${id}/hr-acknowledge`); kpiOpenHrPipQueue(); }
    catch(e){ alert(e.message); }
  };

  // ── Custom KPI add (super_admin only) ───────────────────────────────────
  window.kpiOpenCustomKpiCreate = function(){
    kpiAddonOpen('+ Add Custom KPI',
      `<input id="ck_key" placeholder="kpi_key (snake_case, 3–40 chars)" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;"/>
       <input id="ck_name" placeholder="Display name" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;"/>
       <textarea id="ck_desc" rows="2" placeholder="Description" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;"></textarea>
       <select id="ck_dir" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin-bottom:6px;">
         <option value="higher_better">higher_better</option><option value="lower_better">lower_better</option></select>
       <label><input type="checkbox" id="ck_comp"/> Include in composite</label>
       <input id="ck_weight" type="number" placeholder="Composite weight %" value="0" style="width:100%;padding:8px;border:1px solid var(--border);border-radius:6px;margin:6px 0;"/>
       <label><input type="checkbox" id="ck_safety"/> Safety-critical</label>
       <hr/>
       <p style="font-size:12px;color:var(--muted);">Initial threshold (applied to all tiers):</p>
       <div style="display:flex;gap:6px;">
         <input id="ck_g" type="number" placeholder="Green" style="flex:1;padding:6px;border:1px solid var(--border);border-radius:6px;"/>
         <input id="ck_a" type="number" placeholder="Amber band" style="flex:1;padding:6px;border:1px solid var(--border);border-radius:6px;"/>
         <input id="ck_r" type="number" placeholder="Red floor" style="flex:1;padding:6px;border:1px solid var(--border);border-radius:6px;"/>
       </div>
       <div style="text-align:right;margin-top:10px;">
         <button class="btn btn-primary" onclick="kpiSaveCustomKpi()">Create</button>
       </div>`);
  };
  window.kpiSaveCustomKpi = async function(){
    const g = parseFloat(document.getElementById('ck_g').value||0);
    const a = parseFloat(document.getElementById('ck_a').value||0);
    const r = parseFloat(document.getElementById('ck_r').value||0);
    const body = {
      kpi_key: document.getElementById('ck_key').value.trim(),
      display_name: document.getElementById('ck_name').value.trim(),
      description: document.getElementById('ck_desc').value.trim(),
      direction: document.getElementById('ck_dir').value,
      in_composite: document.getElementById('ck_comp').checked ? 1 : 0,
      composite_weight_pct: parseFloat(document.getElementById('ck_weight').value||0),
      safety_critical: document.getElementById('ck_safety').checked ? 1 : 0,
      thresholds: [
        {tier:'level_1', green:g, amber_band:a, red_floor:r},
        {tier:'level_2', green:g, amber_band:a, red_floor:r},
        {tier:'level_3', green:g, amber_band:a, red_floor:r},
        {tier:'ops_manager', green:g, amber_band:a, red_floor:r},
      ],
    };
    try { await kpiAddonApi('POST', '/api/admin/kpi/definitions/custom', body); kpiAddonClose(); alert('Custom KPI created. Reload to see in dashboards.'); }
    catch(e){ alert(e.message); }
  };

  // ── Manual KPI entry grid ───────────────────────────────────────────────
  window.kpiOpenManualEntry = async function(periodKey){
    try {
      const defs = await kpiAddonApi('GET', '/api/admin/kpi/definitions');
      const manualKpis = (defs.definitions || []).filter(d => d.compute_kind === 'manual');
      if (manualKpis.length === 0) return alert('No manual KPIs defined.');
      const techs = await kpiAddonApi('GET', '/api/admin/kpi/team-scoreboard?period_key=' + encodeURIComponent(periodKey));
      const rows = (techs.rows || []).map(t => {
        const cells = manualKpis.map(k => `<td style="padding:4px;"><input data-tech="${t.tech_id}" data-kpi="${k.kpi_key}" type="number" step="0.01" placeholder="—" style="width:80px;padding:4px;border:1px solid var(--border);border-radius:4px;"/></td>`).join('');
        return `<tr><td style="padding:4px;">${_h(t.name||t.tech_id)}</td>${cells}</tr>`;
      }).join('');
      const headers = manualKpis.map(k => `<th style="padding:6px;">${_h(k.display_name)}</th>`).join('');
      kpiAddonOpen('Manual KPI Entry · ' + periodKey,
        `<table style="width:100%;border-collapse:collapse;font-size:13px;">
           <thead><tr style="background:var(--surface-2);"><th style="padding:6px;text-align:left;">Tech</th>${headers}</tr></thead>
           <tbody>${rows}</tbody>
         </table>
         <div style="text-align:right;margin-top:10px;"><button class="btn btn-primary" onclick="kpiSaveManualGrid('${periodKey}')">Save All</button></div>`);
    } catch(e){ alert(e.message); }
  };
  window.kpiSaveManualGrid = async function(periodKey){
    const inputs = document.querySelectorAll('#kpiAddonBody input[data-tech]');
    const errors = [];
    for (const inp of inputs) {
      const v = inp.value.trim();
      if (!v) continue;
      try {
        await kpiAddonApi('POST', '/api/admin/kpi/scores/manual', {
          tech_id: parseInt(inp.dataset.tech, 10),
          period_key: periodKey,
          kpi_key: inp.dataset.kpi,
          raw_value: parseFloat(v),
          sample_size: 1,
        });
      } catch(e) { errors.push(e.message); }
    }
    if (errors.length) alert('Saved with errors: ' + errors.slice(0,3).join('; '));
    else alert('Saved.');
    kpiAddonClose();
  };
