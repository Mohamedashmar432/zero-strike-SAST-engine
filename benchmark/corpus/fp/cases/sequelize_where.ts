import { BasketModel } from '../models/basket'
import { AddressModel } from '../models/address'

export function basket (req: any, res: any) {
  const id = req.params.id
  BasketModel.findOne({ where: { id }, include: [] }).then((b: any) => res.json(b))
  AddressModel.findOne({ where: { id: req.params.id } }).then((a: any) => res.json(a))
}
