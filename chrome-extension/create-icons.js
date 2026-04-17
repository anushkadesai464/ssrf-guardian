// create-icons.js
// Run this once to generate the icon PNG files
// node create-icons.js

import { createCanvas } from 'canvas'
import { writeFileSync } from 'fs'

function createIcon(size) {
  const canvas = createCanvas(size, size)
  const ctx = canvas.getContext('2d')

  // Dark background circle
  ctx.fillStyle = '#0f1117'
  ctx.beginPath()
  ctx.arc(size/2, size/2, size/2, 0, Math.PI * 2)
  ctx.fill()

  // Red shield shape
  ctx.fillStyle = '#ff4757'
  ctx.beginPath()
  ctx.arc(size/2, size/2, size * 0.38, 0, Math.PI * 2)
  ctx.fill()

  // White G letter
  ctx.fillStyle = '#ffffff'
  ctx.font = `bold ${size * 0.45}px Arial`
  ctx.textAlign = 'center'
  ctx.textBaseline = 'middle'
  ctx.fillText('G', size/2, size/2 + size * 0.03)

  return canvas.toBuffer('image/png')
}

writeFileSync('icon16.png', createIcon(16))
writeFileSync('icon48.png', createIcon(48))
writeFileSync('icon128.png', createIcon(128))
console.log('Icons created!')