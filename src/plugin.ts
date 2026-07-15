/// <reference types="@penpot/plugin-types" />

penpot.ui.open('DömösAiTech Plugin', `plugin.html`, {
  width: 400,
  height: 500,
})

penpot.ui.onMessage<{ type: string; payload?: unknown }>((message) => {
  switch (message.type) {
    case 'get-selection': {
      const selection = penpot.selection.map((shape) => ({
        id: shape.id,
        name: shape.name,
        type: 'shape',
      }))
      penpot.ui.sendMessage({ type: 'selection', payload: selection })
      break
    }

    case 'create-rect': {
      const rect = penpot.createRectangle()
      rect.name = 'Új téglalap'
      rect.x = 100
      rect.y = 100
      rect.resize(200, 150)
      rect.fills = [{ fillColor: '#4361ee' }]
      penpot.ui.sendMessage({ type: 'done', payload: 'Téglalap létrehozva' })
      break
    }

    case 'hello': {
      penpot.ui.sendMessage({
        type: 'hello',
        payload: 'Helló, DömösAiTech!',
      })
      break
    }

    default:
      penpot.ui.sendMessage({ type: 'error', payload: `Ismeretlen üzenet: ${message.type}` })
  }
})
