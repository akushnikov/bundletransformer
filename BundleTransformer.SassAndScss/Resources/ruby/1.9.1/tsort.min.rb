#--
# tsort.rb - provides a module for topological sorting and strongly connected components.
#++
#
module TSort
  class Cyclic < StandardError
  end
  def tsort
    result = []
    tsort_each {|element| result << element}
    result
  end
  def tsort_each # :yields: node
    each_strongly_connected_component {|component|
      if component.size == 1
        yield component.first
      else
        raise Cyclic.new("topological sort failed: #{component.inspect}")
      end
    }
  end
  def strongly_connected_components
    result = []
    each_strongly_connected_component {|component| result << component}
    result
  end
  def each_strongly_connected_component # :yields: nodes
    id_map = {}
    stack = []
    tsort_each_node {|node|
      unless id_map.include? node
        each_strongly_connected_component_from(node, id_map, stack) {|c|
          yield c
        }
      end
    }
    nil
  end
  def each_strongly_connected_component_from(node, id_map={}, stack=[]) # :yields: nodes
    minimum_id = node_id = id_map[node] = id_map.size
    stack_length = stack.length
    stack << node
    tsort_each_child(node) {|child|
      if id_map.include? child
        child_id = id_map[child]
        minimum_id = child_id if child_id && child_id < minimum_id
      else
        sub_minimum_id =
          each_strongly_connected_component_from(child, id_map, stack) {|c|
            yield c
          }
        minimum_id = sub_minimum_id if sub_minimum_id < minimum_id
      end
    }
    if node_id == minimum_id
      component = stack.slice!(stack_length .. -1)
      component.each {|n| id_map[n] = nil}
      yield component
    end
    minimum_id
  end
  def tsort_each_node # :yields: node
    raise NotImplementedError.new
  end
  def tsort_each_child(node) # :yields: child
    raise NotImplementedError.new
  end
end