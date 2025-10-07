(function(){
  'use strict';

  function available(state, phase){
    var count = 0;
    for(var u in state.published){
      var map = state.published[u] || {};
      for(var k in map){
        var it = map[k];
        if(it && it.phase === phase && it.status === 'pending') count++;
      }
    }
    return count;
  }

  function takenBy(state, key){
    for(var u in state.published){
      var it = state.published[u][key];
      if(it && it.status === 'accepted') return u;
    }
    return null;
  }

  function assignOne(state, person, logs, phase){
    phase = phase || 'm';
    var map = state.published[person] || {};
    var items = Object.keys(map).map(function(k){ return {k:k, it:map[k]}; })
      .filter(function(o){ return o.it.phase === phase && o.it.status === 'pending'; })
      .sort(function(a,b){ return (a.it.level - b.it.level) || (a.it.alt - b.it.alt); });
    for(var i=0;i<items.length;i++){
      var k = items[i].k;
      var current = takenBy(state,k);
      if(current){
        if(map[k].status === 'pending'){
          map[k].status = 'refused';
          map[k].ts = Date.now();
          logs.push({type:'refuse',user:person,key:k});
          state.audit.push({ts:Date.now(),action:'refuse',by:'auto',user:person,key:k});
        }
        for(var o in state.published){
          var it = state.published[o][k];
          if(o!==current && it && it.status==='pending'){
            it.status='refused';
            it.ts = Date.now();
            logs.push({type:'refuse',user:o,key:k});
            state.audit.push({ts:Date.now(),action:'refuse',by:'auto',user:o,key:k});
          }
        }
        continue;
      }
      map[k].status = 'accepted';
      map[k].ts = Date.now();
      logs.push({type:'assign',user:person,key:k});
      state.audit.push({ts:Date.now(),action:'assign',by:'auto',user:person,key:k});
      for(var k2 in map){
        if(k2!==k){
          var it2 = map[k2];
          if(it2.phase===phase && it2.status==='pending' && it2.level===map[k].level){
            it2.status='refused';
            it2.ts = Date.now();
            logs.push({type:'refuse',user:person,key:k2});
            state.audit.push({ts:Date.now(),action:'refuse',by:'auto',user:person,key:k2});
          }
        }
      }
      for(var other in state.published){
        if(other===person) continue;
        var ot = state.published[other][k];
        if(ot && ot.status==='pending'){
          ot.status='refused';
          ot.ts = Date.now();
          logs.push({type:'refuse',user:other,key:k});
          state.audit.push({ts:Date.now(),action:'refuse',by:'auto',user:other,key:k});
        }
      }
      return k;
    }
    return null;
  }

  function countStatus(state, phase){
    phase = phase || 'm';
    var assigned = 0;
    var pending = 0;
    for(var u in state.published){
      var map = state.published[u] || {};
      for(var k in map){
        var it = map[k];
        if(it && it.phase === phase){
          if(it.status === 'accepted') assigned++;
          if(it.status === 'pending') pending++;
        }
      }
    }
    return {assigned:assigned, pending:pending};
  }

  function countStatuses(state, phases){
    phases = phases && phases.length ? phases : ['m'];
    var total = {assigned:0, pending:0};
    phases.forEach(function(ph){
      var c = countStatus(state, ph);
      total.assigned += c.assigned;
      total.pending += c.pending;
    });
    return total;
  }

  function run(state, options, tick){
    options = options || {};
    var m = options.m || 0;
    var b = options.b || 0;
    var x = options.x || 0; // max good bonus per loop
    var loopsPerPerson = options.loops || 1;

    var people = (options.people || []).slice();
    var order = options.order === 'desc' ? -1 : 1;
    people.sort(function(a,b2){ return a.localeCompare(b2) * order; });
    if(options.start){
      var idx = people.indexOf(options.start);
      if(idx > 0){
        people = people.slice(idx).concat(people.slice(0, idx));
      }
    }
    var logs = [];
    var onMap = {};
    people.forEach(function(p){ onMap[p]=true; });
    var personIdx = 0;
    var loop = 0;
    var stopped = false;
    var timer;
    var runCounts = {assigned:0, m:0, x:0, y:0};

    function anyOn(){
      for(var p in onMap){ if(onMap[p]) return true; }
      return false;
    }

    function countsInfo(){
      var base = countStatuses(state, ['m','x','y']);
      return {
        assigned: runCounts.assigned,
        pending: base.pending,
        m: runCounts.m,
        x: runCounts.x,
        y: runCounts.y
      };
    }

    function end(status){
      if(typeof tick === 'function') tick(status, logs, {counts:countsInfo(), loop: loop+1, on:onMap});
    }

    function runLoop(){
      if(stopped){ end('stopped'); return; }
      var counts = countStatuses(state, ['m','x','y']);
      if(counts.pending === 0 || !anyOn()){ end('done'); return; }

      var person = people[personIdx];
      var assignedThisLoop=0;
      if(onMap[person]){
        for(var l=0;l<loopsPerPerson;l++){
          if(available(state,'m') < m){
            logs.push({type:'info',user:person,msg:'gardes insuffisantes'});
            onMap[person]=false;
            break;
          }
          var phasesLoop=[];
          var i;
          for(i=0;i<m;i++) phasesLoop.push('m');
          if(b>0){
            var goodAvail=available(state,'x');
            var badAvail=available(state,'y');
            var totalAvail=goodAvail + badAvail;
            var goodToAssign=0;
            var badToAssign=0;
            // Allow assignment when total bonuses are missing but
            // the maximum number of good bonuses is available.
            if(totalAvail < b){
              if(goodAvail >= x){
                goodToAssign=x;
                badToAssign=Math.min(b - goodToAssign, badAvail);
              }else{
                logs.push({type:'info',user:person,msg:'bonus insuffisants'});
                onMap[person]=false;
                break;
              }
            }else{
              goodToAssign=Math.min(x, goodAvail, b);
              badToAssign=b - goodToAssign;
              if(badAvail < badToAssign){
                logs.push({type:'info',user:person,msg:'bonus insuffisants'});
                onMap[person]=false;
                break;
              }
            }
            for(i=0;i<goodToAssign;i++) phasesLoop.push('x');
            for(i=0;i<badToAssign;i++) phasesLoop.push('y');
          }
          phasesLoop.forEach(function(ph){
            var k = assignOne(state, person, logs, ph);
            if(k){
              runCounts.assigned++;
              assignedThisLoop++;
              if(ph==='m') runCounts.m++;
              else if(ph==='x') runCounts.x++;
              else if(ph==='y') runCounts.y++;
            }
          });
        }
      }
      personIdx++;
      if(personIdx >= people.length){ personIdx = 0; loop++; }
      if(typeof tick === 'function') tick('tick', logs, {counts:countsInfo(), loop: loop+1, on:onMap});
      var delay=assignedThisLoop>0 ? assignedThisLoop*500 : 0;
      timer = setTimeout(runLoop, delay);
    }

    timer = setTimeout(runLoop, 0);
    return {
      stop: function(){ stopped=true; clearTimeout(timer); end('stopped'); }
    };
  }

  window.attribution = {
    run: run
  };
})();
