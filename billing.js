const $ = (s) => document.querySelector(s)

async function startCheckout(plan) {
  const button = document.querySelector(`[data-buy-plan="${plan}"]`)
  const old = button.textContent
  button.disabled = true
  button.textContent = 'Opening checkout…'
  try {
    const response = await fetch('/api/billing/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ plan }),
    })
    const data = await response.json()
    if (!response.ok) throw new Error(data.error || 'Checkout unavailable')
    location.href = data.checkout_url
  } catch (error) {
    alert(error.message)
    button.disabled = false
    button.textContent = old
  }
}

document.querySelectorAll('[data-buy-plan]').forEach((button) => {
  button.addEventListener('click', () => startCheckout(button.dataset.buyPlan))
})
