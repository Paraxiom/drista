/**
 * ChannelList - Sidebar channel list component
 */

import * as store from './store.js';

export function ChannelList() {
  const channelList = store.channels.value;
  const currentId = store.currentChannelId.value;

  return (
    <aside class="lcars-sidebar">
      <div class="lcars-bar lcars-sidebar-header">CHANNELS</div>
      <div class="lcars-sidebar-content">
        {channelList.map(ch => (
          <ChannelItem
            key={ch.id}
            channel={ch}
            active={ch.id === currentId}
            onClick={() => {
              store.setCurrentChannel(ch.id);
              store.markRead(ch.id);
            }}
          />
        ))}
      </div>
      <div class="lcars-bar lcars-sidebar-footer">
        <button class="lcars-button lcars-small" onClick={() => { store.activeModal.value = 'newDM'; }}>
          NEW DM
        </button>
        <button class="lcars-button lcars-small" onClick={() => { store.activeModal.value = 'newGroup'; }}>
          NEW GROUP
        </button>
      </div>
    </aside>
  );
}

function ChannelItem({ channel, active, onClick }) {
  const icon = channel.channelType === 'direct' ? '◈' :
               channel.channelType === 'forum' ? '#' : '◉';
  const encrypted = channel.encrypted ? '🔒' : '';

  return (
    <div class={`channel-item ${active ? 'active' : ''}`} onClick={onClick}>
      <div class="channel-icon">{icon}</div>
      <span class="channel-name">{channel.name} {encrypted}</span>
      {channel.unreadCount > 0 && (
        <span class="channel-unread">{channel.unreadCount}</span>
      )}
    </div>
  );
}
