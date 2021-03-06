defmodule Harald.HCI.Commands.ControllerAndBaseband.WriteSimplePairingMode do
  @moduledoc """
  Reference: version 5.2, Vol 4, Part E, 7.3.59.
  """

  alias Harald.HCI.Commands.Command

  @behaviour Command

  @impl Command
  def encode(%{simple_pairing_mode: true}), do: {:ok, <<1>>}
  def encode(%{simple_pairing_mode: false}), do: {:ok, <<0>>}

  @impl Command
  def decode(<<1>>), do: {:ok, %{simple_pairing_mode: true}}
  def decode(<<0>>), do: {:ok, %{simple_pairing_mode: false}}

  @impl Command
  def decode_return_parameters(<<status>>), do: {:ok, %{status: status}}

  @impl Command
  def encode_return_parameters(%{status: status}), do: {:ok, <<status>>}

  @impl Command
  def ocf(), do: 0x56
end
