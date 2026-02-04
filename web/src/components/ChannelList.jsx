/**
 * ChannelList - Sidebar channel list component
 */

import * as store from './store.js';

export function ChannelList({ mobileOpen, onChannelSelect }) {
  const channelList = store.channels.value;
  const currentId = store.currentChannelId.value;

  const handleChannelClick = (ch) => {
    store.setCurrentChannel(ch.id);
    store.markRead(ch.id);
    if (onChannelSelect) onChannelSelect();
  };

  return (
    <aside class={`lcars-sidebar ${mobileOpen ? 'mobile-open' : ''}`}>
      <div class="lcars-bar lcars-sidebar-header">CHANNELS</div>
      <div class="lcars-sidebar-content">
        {channelList.map(ch => (
          <ChannelItem
            key={ch.id}
            channel={ch}
            active={ch.id === currentId}
            onClick={() => handleChannelClick(ch)}
          />
        ))}
      </div>
      <div class="lcars-bar lcars-sidebar-footer">
        <button class="lcars-button lcars-small" onClick={() => { store.activeModal.value = 'newDM'; onChannelSelect?.(); }}>
          NEW DM
        </button>
        <button class="lcars-button lcars-small" onClick={() => { store.activeModal.value = 'newGroup'; onChannelSelect?.(); }}>
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
  const isDefault = channel.id === '#drista';

  function handleRemove(e) {
    e.stopPropagation();
    if (confirm(`Remove channel "${channel.name}"?`)) {
      store.removeChannel(channel.id);
    }
  }

  return (
    <div class={`channel-item ${active ? 'active' : ''}`} onClick={onClick}>
      <div class="channel-icon">{icon}</div>
      <span class="channel-name">{channel.name} {encrypted}</span>
      {channel.unreadCount > 0 && (
        <span class="channel-unread">{channel.unreadCount}</span>
      )}
      {!isDefault && (
        <button class="channel-remove" onClick={handleRemove} title="Remove channel">×</button>
      )}
    </div>
  );
}
