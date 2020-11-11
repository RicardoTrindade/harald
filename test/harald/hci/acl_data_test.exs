defmodule Harald.HCI.ACLDataTest do
  use ExUnit.Case, async: true
  alias Harald.HCI.ACLData
  alias Harald.Host.{ATT, L2CAP}
  alias Harald.Host.ATT.{ExchangeMTUReq, ReadByGroupTypeRsp}

  test "decode/1" do
    handle = <<1, 2::size(4)>>
    encoded_broadcast_flag = 0b00
    encoded_packet_boundary_flag = 0b10

    decoded_packet_boundary_flag = %{
      description:
        "First automatically flushable packet of a higher layer message (start of an automatically-flushable L2CAP PDU).",
      value: encoded_packet_boundary_flag
    }

    decoded_broadcast_flag = %{
      description: "Point-to-point (ACL-U, AMP-U, or LE-U)",
      value: encoded_broadcast_flag
    }

    decoded_mtu = 185
    decoded_exchange_mtu_rsp = 2

    encoded_att_data = <<
      decoded_exchange_mtu_rsp,
      decoded_mtu::little-size(16)
    >>

    decoded_att_length = byte_size(encoded_att_data)
    decoded_channel_id = 4

    encoded_l2cap_data = <<
      decoded_att_length::little-size(16),
      decoded_channel_id::little-size(16),
      encoded_att_data::binary
    >>

    decoded_att_opcode = ExchangeMTUReq
    decoded_att_parameters = %{client_rx_mtu: 185}
    {:ok, decoded_att} = ATT.new(decoded_att_opcode, decoded_att_parameters)
    {:ok, decoded_l2cap_data} = L2CAP.new(ATT, decoded_att)
    data_total_length = byte_size(encoded_l2cap_data)

    decoded_acl_data = %ACLData{
      handle: <<8, 1::size(4)>>,
      packet_boundary_flag: decoded_packet_boundary_flag,
      broadcast_flag: decoded_broadcast_flag,
      data_total_length: data_total_length,
      data: decoded_l2cap_data
    }

    encoded_acl_data = <<
      2,
      handle::bits-size(12),
      encoded_packet_boundary_flag::size(2),
      encoded_broadcast_flag::size(2),
      data_total_length::little-size(16),
      encoded_l2cap_data::binary
    >>

    assert {:ok, decoded_acl_data} == ACLData.decode(encoded_acl_data)
  end

  describe "encode/1" do
    test "foo" do
      hci_packet_type = 2
      handle = <<1, 2::size(4)>>
      encoded_broadcast_flag = 0b00
      encoded_packet_boundary_flag = 0b01

      decoded_packet_boundary_flag = %{
        description: "Continuing fragment of a higher layer message",
        value: encoded_packet_boundary_flag
      }

      decoded_broadcast_flag = %{
        description: "Point-to-point (ACL-U, AMP-U, or LE-U)",
        value: encoded_broadcast_flag
      }

      decoded_mtu = 185
      decoded_exchange_mtu_rsp = 2

      encoded_att_data = <<
        decoded_exchange_mtu_rsp,
        decoded_mtu::little-size(16)
      >>

      decoded_att_length = byte_size(encoded_att_data)
      decoded_channel_id = 4

      encoded_l2cap_data = <<
        decoded_att_length::little-size(16),
        decoded_channel_id::little-size(16),
        encoded_att_data::binary
      >>

      decoded_att_opcode = ExchangeMTUReq
      decoded_att_parameters = %{client_rx_mtu: 185}
      {:ok, decoded_att} = ATT.new(decoded_att_opcode, decoded_att_parameters)
      {:ok, decoded_l2cap_data} = L2CAP.new(ATT, decoded_att)
      data_total_length = byte_size(encoded_l2cap_data)

      decoded_acl_data = %ACLData{
        handle: handle,
        packet_boundary_flag: decoded_packet_boundary_flag,
        broadcast_flag: decoded_broadcast_flag,
        data_total_length: data_total_length,
        data: decoded_l2cap_data
      }

      <<h1::size(4), h2::size(4), h3::size(4)>> = handle
      flags = <<encoded_broadcast_flag::size(2), encoded_packet_boundary_flag::size(2)>>

      handle_and_flags = <<
        h1::size(4),
        h3::size(4),
        flags::bits-size(4),
        h2::size(4)
      >>

      encoded_acl_data = <<
        hci_packet_type::size(8),
        handle_and_flags::binary-little-size(2),
        data_total_length::little-size(16),
        encoded_l2cap_data::binary
      >>

      assert {:ok, encoded_acl_data} == ACLData.encode(decoded_acl_data)
    end

    test "Bar" do
      decoded_broadcast_flag = %{
        value: 0b00
      }

      decoded_packet_boundary_flag = %{
        value: 0b10
      }

      {:ok, decoded_att} =
        ATT.new(ReadByGroupTypeRsp, %{
          length: 6,
          attribute_data_list: [
            %{attribute_handle: 1, attribute_value: 0x1800, end_group_handle: 5},
            %{attribute_handle: 6, attribute_value: 0x1801, end_group_handle: 9},
            %{attribute_handle: 0x10, attribute_value: 0x180A, end_group_handle: 0x14}
          ]
        })

      {:ok, decoded_l2cap_data} = L2CAP.new(ATT, decoded_att)
      {:ok, encoded_l2cap_data} = L2CAP.encode(decoded_l2cap_data)
      data_total_length = byte_size(encoded_l2cap_data)

      decoded_acl_data = %ACLData{
        handle: <<64::little-size(12)>>,
        packet_boundary_flag: decoded_packet_boundary_flag,
        broadcast_flag: decoded_broadcast_flag,
        data_total_length: data_total_length,
        data: decoded_l2cap_data
      }

      expected_bin =
        Base.encode16(
          <<2, 64, 32, 24, 0, 20, 0, 4, 0, 17, 6, 1, 0, 5, 0, 0, 24, 6, 0, 9, 0, 1, 24, 16, 0, 20,
            0, 10, 24>>
        )

      {:ok, bin} = ACLData.encode(decoded_acl_data)
      bin = Base.encode16(bin)
      assert bin == expected_bin
    end
  end
end
